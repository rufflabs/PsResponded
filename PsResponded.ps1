<#
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

#>
[CmdletBinding(DefaultParameterSetName = 'Request')]
param(
    [parameter(Mandatory = $true,
        ParameterSetName = 'Request')] 
    [string]$Hostname,
    [parameter(ParameterSetName = 'Request')]
    [int]$MinimumWait = 420,
    [parameter(ParameterSetName = 'Request')]
    [int]$MaximumWait = 7200,
    [parameter(ParameterSetName = 'Request')]
    [int]$DwellTime = 60,
    [parameter(ParameterSetName = 'Unregister')]
    [switch]$Unregister
)

begin {
    $EventSource = "PsResponded" # Report as this Source in Event Logs
    $EventLog = "Application"    # The Event Log to write to.
    $EventIdMessage = 5005       # Event ID for general messages.
    $EventIdStopped = 5006       # Event ID for when a listener is shutdown.
    $EventIdResponded = 5007     # Event ID for when a Responder-esque response is seen.

    # Confirm $Hostname doesn't currently exist.
    $Request = Resolve-DnsName -Name $Hostname -LlmnrNetbiosOnly -ErrorAction SilentlyContinue
    
    if($Request) {
        $SourceIP = ($Request | Select-Object -ExpandProperty IPAddress) -join '|'
        Write-Error -Message "Indicated hostname '$($Hostname)' is currently resolving to $($SourceIP).`nPsResponded is exiting."
        exit
    }

    function Test-Administrator {
        <#
        .SYNOPSIS
            Returns true if the current user has Administrator privileges, false otherwise.
        #>
        $CurrentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
        (New-Object Security.Principal.WindowsPrincipal $CurrentUser).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
    }

    if(Test-Administrator) {
        # Setup Event Source if needed
        if([System.Diagnostics.EventLog]::SourceExists($EventSource)){
            # If the Event Source is already registered, use the Event Log it's registered to.
            $EventLog = [System.Diagnostics.EventLog]::LogNameFromSourceName($EventSource,"localhost")
            Write-Output "Logging to $($EventLog) Event Log as Event Source $($EventSource)."
        }else{
            # Register the Event Source to the specified Event Log if it isn't already registered.
            New-EventLog -LogName $EventLog -Source $EventSource
            Write-Output "Registered Event Source ($($EventSource)) in Event Log ($($EventLog))"
        }
    }else{
        Write-Error -Message "Requires Administrator privileges.`nPlease run this script as Administrator."
    }

    $Message = "Starting PsResponded requesting LLMNR for hostname: $($Hostname)."
    Write-EventLog -Message $Message -Source $EventSource -LogName $EventLog -EventId $EventIdMessage -EntryType Information
    Write-Verbose -Message $Message
}

process {
    if($Unregister) {
        # Remove the Event Source registration
        Remove-EventLog -Source $EventSource
        Write-Output "Event Source $($EventSource) has been unregistered from Event Logs."
        exit
    }

    while($true) {
        $Request = Resolve-DnsName -Name $Hostname -LlmnrNetbiosOnly -ErrorAction SilentlyContinue
        
        if($Request) {
            # Response was detected!
            $SourceIP = ($Request | Select-Object -ExpandProperty IPAddress) -join '|'
            $Message = "SourceIP=$($SourceIP);Message=Received response to mDNS request for $($Hostname) from $($SourceIP)."
            Write-EventLog -Message $Message -Source $EventSource -LogName $EventLog -EventId $EventIdResponded -EntryType Information
            Write-Verbose -Message $Message

            Start-Sleep -Seconds $DwellTime
        }else{
            # Wait a random amount of time before the next request. This is to avoid anyone listening
            # from determining if this is an automated request.
            $WaitTime = Get-Random -Minimum $MinimumWait -Maximum $MaximumWait
            Write-Verbose -Message "Waiting for $($WaitTime) seconds."
            Start-Sleep -Seconds $WaitTime
        }
    }
}

end {
    $Message = "Stopping PsResponded."
    Write-EventLog -Message $Message -Source $EventSource -LogName $EventLog -EventId $EventIdStopped -EntryType Information
    Write-Verbose -Message$Message
}