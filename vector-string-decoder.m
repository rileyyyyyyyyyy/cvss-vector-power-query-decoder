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
in
    kvTable
