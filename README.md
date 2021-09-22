# Kernel-Snooping

Main: https://medium.com/@VL1729_JustAT3ch

Removing Process Creation Kernel Callbacks:

Targeting EDR registered callbacks for Process creation(PsSetCreateProcessNotifyRoutine).

External componenets used:

vulnerable driver MSI Afterburner RTCore64 (CVE-2019–16098) is used.

Notes:

1. Currently no built in functionality provided for loading the driver since the point here is mainly how to locate      array(PspCreateProcessNotifyRoutine) which holds the callbacks.

2. Any vulnerable driver which provides read-what-where functionality will work(No shortage of those :)). 

