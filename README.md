# TraceControl
powershell cmdlets to control capture etw traces and analyze them.

basically you can run:
H:\TestMimalloc\Testmimalloc.exe

wpr -start H:\TestTraces\TraceAnalyzer\profiles\Mimalloc.wprp -filemode -recordtempto H:\TestTraces\ETL\Temp
wpr -stop H:\TestTraces\ETL\Test_fb0231b3-3fc9-4c9f-b115-c8412d0928af_Mimalloc.etl

import-module "\TraceAnalyzer.dll" -DisableNameChecking
$env:_NT_SYMBOL_PATH="H:\TestMimalloc"
$r = Analyze-Mimalloc -FilePath H:\TestTraces\ETL\Test_fb0231b3-3fc9-4c9f-b115-c8412d0928af_Mimalloc.etl  -ProcessId {your process id}
$r
