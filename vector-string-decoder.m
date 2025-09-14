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

    // mapping tables
    map_v2 = #table({"Metric","Code","Name","Readable"}, {
        {"AV","N","Access Vector","Network"}, {"AV","A","Access Vector","Adjacent Network"}, {"AV","L","Access Vector","Local"},
        {"AC","H","Access Complexity","High"}, {"AC","M","Access Complexity","Medium"}, {"AC","L","Access Complexity","Low"},
        {"Au","N","Authentication","None"}, {"Au","S","Authentication","Single"}, {"Au","M","Authentication","Multiple"},
        {"C","N","Confidentiality","None"}, {"C","P","Confidentiality","Partial"}, {"C","C","Confidentiality","Complete"},
        {"I","N","Integrity","None"}, {"I","P","Integrity","Partial"}, {"I","C","Integrity","Complete"},
        {"A","N","Availability","None"}, {"A","P","Availability","Partial"}, {"A","C","Availability","Complete"}
    }),
    map_v3 = #table({"Metric","Code","Name","Readable"}, {
        {"AV","N","Attack Vector","Network"}, {"AV","A","Attack Vector","Adjacent"}, {"AV","L","Attack Vector","Local"}, {"AV","P","Attack Vector","Physical"},
        {"AC","L","Attack Complexity","Low"}, {"AC","H","Attack Complexity","High"},
        {"PR","N","Privileges Required","None"}, {"PR","L","Privileges Required","Low"}, {"PR","H","Privileges Required","High"},
        {"UI","N","User Interaction","None"}, {"UI","R","User Interaction","Required"},
        {"S","U","Scope","Unchanged"}, {"S","C","Scope","Changed"},
        {"C","H","Confidentiality","High"}, {"C","L","Confidentiality","Low"}, {"C","N","Confidentiality","None"},
        {"I","H","Integrity","High"}, {"I","L","Integrity","Low"}, {"I","N","Integrity","None"},
        {"A","H","Availability","High"}, {"A","L","Availability","Low"}, {"A","N","Availability","None"}
    }),
    map_v4 = #table({"Metric","Code","Name","Readable"}, {
        {"AV","N","Attack Vector","Network"}, {"AV","A","Attack Vector","Adjacent"}, {"AV","L","Attack Vector","Local"}, {"AV","P","Attack Vector","Physical"},
        {"AC","L","Attack Complexity","Low"}, {"AC","H","Attack Complexity","High"},
        {"AT","N","Attack Requirements","None"}, {"AT","P","Attack Requirements","Present"},
        {"PR","N","Privileges Required","None"}, {"PR","L","Privileges Required","Low"}, {"PR","H","Privileges Required","High"},
        {"UI","N","User Interaction","None"}, {"UI","P","User Interaction","Passive"}, {"UI","A","User Interaction","Active"},
        {"VC","H","Vulnerable Confidentiality","High"}, {"VC","L","Vulnerable Confidentiality","Low"}, {"VC","N","Vulnerable Confidentiality","None"},
        {"VI","H","Vulnerable Integrity","High"}, {"VI","L","Vulnerable Integrity","Low"}, {"VI","N","Vulnerable Integrity","None"},
        {"VA","H","Vulnerable Availability","High"}, {"VA","L","Vulnerable Availability","Low"}, {"VA","N","Vulnerable Availability","None"},
        {"SC","H","Subsequent Confidentiality","High"}, {"SC","L","Subsequent Confidentiality","Low"}, {"SC","N","Subsequent Confidentiality","None"},
        {"SI","H","Subsequent Integrity","High"}, {"SI","L","Subsequent Integrity","Low"}, {"SI","N","Subsequent Integrity","None"},
        {"SA","H","Subsequent Availability","High"}, {"SA","L","Subsequent Availability","Low"}, {"SA","N","Subsequent Availability","None"}
    }),
    mapAll = Table.Combine({map_v2, map_v3, map_v4}), // combine mapping tables into one table

    // joins key-value pairs of input vector string with the mapping tables
    joined   = Table.NestedJoin(kvTable, {"Metric","Code"}, mapAll, {"Metric","Code"}, "m", JoinKind.LeftOuter),
    expanded = Table.ExpandTableColumn(joined, "m", {"Name","Readable"}, {"Name","Readable"}),
    known    = Table.SelectRows(expanded, each [Name] <> null),
    known2   = Table.SelectColumns(known, {"Name","Readable"}),
    
    // squashes table down into a single dimension
    pivoted  =
        if Table.IsEmpty(known2) then #table({"Placeholder"}, {{null}})
        else
            let
                withKey  = Table.AddColumn(known2, "__key__", each 1),
                cols     = List.Distinct(withKey[Name]),
                pvt      = Table.Pivot(withKey, cols, "Name", "Readable", each List.First(_)),
                cleaned  = Table.RemoveColumns(pvt, {"__key__"})
            in
                cleaned,
in
    pivoted
