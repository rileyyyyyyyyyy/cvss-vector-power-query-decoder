(vector as nullable text) as table =>
let
    // split into components
    rawVectorString = if vector=null then "" else Text.Trim(vector),
    versionHint = if Text.StartsWith(rawVectorString, "CVSS:")
                  then try Text.BeforeDelimiter(Text.AfterDelimiter(rawVectorString, "CVSS:"), "/") otherwise null
                  else null,
    // strip the version
    noPref  = if Text.StartsWith(rawVectorString, "CVSS:")
              then
                  let pos = Text.PositionOf(rawVectorString, "/")
                  in if pos <> -1 then Text.Range(rawVectorString, pos + 1) else ""
              else rawVectorString,
    // get the metric pairs
    parts = List.RemoveNulls(
                List.Transform(Text.Split(noPref, "/"),
                each let kv = Text.Split(_,":") in if List.Count(kv)=2 then kv else null)
            ),
    // create table for key-value pairs
    kvTable = if List.Count(parts)=0 then #table({"Metric","Code"}, {})
              else Table.FromColumns({ List.Transform(parts, each _{0}), List.Transform(parts, each _{1}) }, {"Metric","Code"}),

    // detect version from context
    metrics = if Table.IsEmpty(kvTable) then {} else List.Distinct(kvTable[Metric]),
    detected =
        if versionHint <> null then versionHint
        else if List.ContainsAny(metrics, {"AT","VC","VI","VA","SC","SI","SA"}) then "4.0"
        else if List.ContainsAny(metrics, {"PR","UI","S"}) then "3.x"
        else if List.Contains(metrics, "Au") then "2.0"
        else "unknown",
in
    detected
