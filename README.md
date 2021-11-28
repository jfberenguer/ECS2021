# ECS2021
KQL session at European Cloud Summit 2021

# LEVEL ONE : Warm-Up

// how to write au query  
SecurityEvent  
// How to comment a line  
//|where TimeGenerated between (datetime(2021-11-01) .. datetime(2021-11-31))  
|where EventID == 4625  
|summarize count() by Account  
|order by count_ desc  

//Hunting Query : Are there any users whose login failed in the last hour?  
SecurityEvent  
| where TimeGenerated > ago(1d)  
| where EventID == 4625 and AccountType =~ ''user''  

//Hunting Query : Are there any login to Azure Portal from outside FR. Display App, country and Identity
// How to use Extend and Project Operators
SigninLogs
|where AppDisplayName contains "azure"
|extend Country = iff(LocationDetails.countryOrRegion == '', 'Unknown country', tostring(LocationDetails.countryOrRegion))  
|where Country != "FR"  
|project AppDisplayName, Country, Identity  

//Hunting Query : search for a specific security event during a specific time interval  
// How to use the Let Statement  
let startDatetime = todatetime("2021-11-24 00:00:00");  
let endDatetime = todatetime("2021-11-30 00:00:00");  
let SecurityEventID = 4625;  
SecurityEvent   
|where EventID == SecurityEventID   
|where TimeGenerated between(startDatetime .. endDatetime)  
|project Computer, Account, TimeGenerated  

//Hunting Query : What are the most common (top 10) accounts used with failed login during last week of November  
// How to use Summarise, count, Order by and take  
SecurityEvent   
|where TimeGenerated between (datetime(2021-11-24) .. datetime(2021-11-30))  
|where EventID == 4625  
|summarize count() by Account  
|order by count_ desc   
|take 10  

//Hunting Query : A graph showing the total number of login errors per day over the last two weeks  
// How to use render to show the result as a Graph  
SecurityEvent   
|where TimeGenerated > ago(14d)  
|where EventID == 4625  
|summarize count() by tostring(EventID), bin(TimeGenerated, 1d)  
| render Timechart   



# LEVEL TWO : GO AHEAD

//Analytic Rule Query : raise an alert if there was at least one change in the registry during the last week. Collect details on Computer, UserName, Event Type,   
// How to parse text data with split and parse_xml  
Event  
| where Source == "Microsoft-Windows-Sysmon"  
| where EventID == 13 //sysmon registry event  
| extend RenderedDescription = tostring(split(RenderedDescription, ":")[0])  
| project TimeGenerated, Source, EventID, Computer, UserName, EventData, RenderedDescription  
| extend EvData = parse_xml(EventData)  
| extend EventDetail = EvData.DataItem.EventData.Data  
| project-away EventData, EvData    
| extend RuleName = EventDetail.[0].["#text"], EventType = EventDetail.[1].["#text"],   
    ProcessId = EventDetail.[4].["#text"], Image = EventDetail.[5].["#text"], TargetObject = EventDetail.[6].["#text"], Details = EventDetail.[7].["#text"]  
    | project-away EventDetail   

//Hunting Query : Show, for each Alert, if there is an associated IP Address and what is the Location  
// How to use mv-expand  
SecurityAlert   
|where entity.Type == "ip"  
|mv-expand entity=todynamic(Entities)  
|extend IPadress = ['entity'].Address  
|extend LocationIPAdress = ['entity'].Location  
|project IPadress, AlertName, AlertSeverity, LocationIPAdress  

//Query : a list of successful queries for the last day, ordered by duration   
// How to Audit Queries , using LAQueryLogs  
LAQueryLogs  
|where TimeGenerated > ago(1d)  
|where ResponseCode == 200  
|project QueryText, ResponseCode, ResponseDurationsMS, ResponseRowCount  
|order by ResponseDurationMS desc  


# LEVEL THREE : FASTEN YOUR SEATBELT

// Hunting Query : During last month, Are there successful and failed login attempts on the same computer with the same account, what is the number of each and in what proportion  
// How to use JOIN  
SecurityEvent   
| where EventID == "4624" and TimeGenerated > ago(30d)  
| summarize SuccessLogOnCount=count() by EventID, Account, Computer  
| project SuccessLogOnCount, Account , Computer  
| join kind = inner (  
     SecurityEvent   
     | where EventID == "4625" and TimeGenerated > ago(30d)  
     | summarize FailedLogOnCount=count() by EventID, Account, Computer  
     | project FailedLogOnCount, Account , Computer  
) on Account  
|project-away Account1, Computer1  
|extend proportion = FailedLogOnCount / SuccessLogOnCount  
|order by proportion desc  

//Hunting Query : Determine if there is a dictionary attack on computers with necessary security updates  
// How to use un Function in a KQL Query  
let machinesWithUpdateNeeded = (){   
    Update  
        |where TimeGenerated >= ago(30d)    
        |where UpdateState has "Needed" and Title contains "security"   
        |summarize Computer=makeset(Computer)  
};  
SecurityDetection  
|where TimeGenerated >= ago(100d)   
| where Description contains "dictionary attack"  
| where Computer in (machinesWithUpdateNeeded) //limit the query to just these computers  
| summarize by Computer  


# LEVEL FOUR : BOSS LEVEL

// Queries that span across workspaces  
// Hot to use UNION  
// How to specify the workspace  
let unionSecurityEvent = () {  
    union (workspace("WorkspaceOne").SecurityAlert), (workspace("WorkspaceTwo").SecurityAlert)  
};  
unionSecurityEvent  
|where TimeGenerated > ago(30d)  
|summarize count() by AlertSeverity, bin(TimeGenerated, 1d)  
|render timechart  

//Query : A graph showing the total number of login errors per day over the last two weeks and the line fit  
// How to use Time series  
// How to use make-series operator  
// How to use series_fit_line()  
let StartDate = now(-15d);  
let EndDate = now();  
SecurityEvent  
| where TimeGenerated between (StartDate..EndDate) and EventID == 4625  
| make-series NumberOfEvent = dcount(tostring(TimeGenerated)) on TimeGenerated in range(StartDate,EndDate, 1d)  
| extend (RSquare,Slope,Variance,RVariance,Interception,LineFit) = series_fit_line(NumberOfEvent)  
|render timechart   
