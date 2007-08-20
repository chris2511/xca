#!/usr/bin/perl
use X11::GUITest qw/StartApp WaitWindowViewable SendKeys GetInputFocus GetWindowName WaitWindowClose/;

my $password = "ThisIsMyPassword";
my $db = "__x.xdb";
unlink $db;


StartApp("./xca $db");
my ($xcaId) = WaitWindowViewable("X Certificate and Key management");

SendKeys($password . "{TAB}" . $password . "{ENT}");
SendKeys("^(c)");
SendKeys("^(l)");
WaitWindowViewable("Open XCA Database");
SendKeys($db . "{ENT}");
WaitWindowViewable("Password");
SendKeys($password  ."{ENT}");
SendKeys("%({F4})");
WaitWindowClose($xcaId, 10);

exec("lib/db_dump", $db);
