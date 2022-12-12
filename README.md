```powershell
.SYNOPSIS
    Periodically sends LLMNR, NetBIOS requests for a known non-existant
    host. If a response is received, this indicates a potential Responder
    spoofing attack and sends an Event ID 5005 to the Event Log.

.DESCRIPTION
    

.PARAMETER Hostname
    Known non-existant hostname, if a response is received to this hostname
    an event is logged.

.PARAMETER Unregister
    Removes the Event Source from the Event Log service.

.PARAMETER MinimumWait
    Minimum seconds to wait between requests.

.PARAMETER MaximumWait
    Maximum seconds to wait between requests.

.PARAMETER DwellTime
    Seconds to wait after receiving a response before another attempt is made.
    Defaults to 60 seconds. 

.EXAMPLE
    Start sending periodic request, waiting between 7 minutes and 2 hours with a
    60 second dwell time between requests when a response is received.

        PS C:\> .\PsResponded.ps1 -Hostname abc123 `
        >> -MinimumWait 420 -MaximumWait 7200 -DwellTime 60

.EXAMPLE
    Unregister the Event Source from Event Logs if not used anymore.

        PS C:\> .\PsResponded.ps1 -Unregister
```