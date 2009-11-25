#!/usr/bin/perl

use strict;
use warnings;

use X11::GUITest qw/StartApp WaitWindowViewable SendKeys
	SetInputFocus WaitWindowClose GetInputFocus GetWindowName
	GetChildWindows ClickWindow/;

my $xcaId;
my $password = "ThisIsMyPassword";
my $db = "__x.xdb";
unlink $db;

sub new_key {
  my $id;
  my ($name, $size, $type) = @_;
  print "name=$name, size=$size, Type=$type\n";
  SendKeys("%(i)");
  $id = WaitWindowViewable("New key");
  SendKeys($name ."{TAB}" .$size ."{TAB}". $type ."{ENT}");
  WaitWindowClose($id, 10);
}

StartApp("./xca $db");
($xcaId) = WaitWindowViewable("X Certificate and Key management");
printf "XCA id: $xcaId\n";
WaitWindowViewable("Password");
SendKeys($password . "{TAB}" . $password . "{ENT}");

SendKeys("%(i)");
my $id = WaitWindowViewable("Import RSA key");
SendKeys("{BS 20}" . "test/key.pem" . "{ENT}");
WaitWindowClose($id, 10);

system("xev -id $xcaId &");

ClickWindow($xcaId);
SendKeys("{SPACE}");

#ClickWindow($xcaId, 100, 110);
#ClickWindow($xcaId, 200, 110);
#ClickWindow($xcaId, 300, 110);

#SendKeys("%({F4})");
#WaitWindowClose($xcaId, 10);

#exec("lib/db_dump", $db);
