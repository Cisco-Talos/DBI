#pragma D option quiet

syscall:::entry
/ pid == $target /
{
    printf("%Y %s[%d] %s\n", walltimestamp, execname, pid, probefunc);
}