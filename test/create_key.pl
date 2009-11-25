#!/usr/bin/perl
use X11::GUITest qw/StartApp WaitWindowViewable SendKeys
	SetInputFocus WaitWindowClose GetInputFocus GetWindowName
	GetChildWindows/;

my $xcaId;
my $password = "ThisIsMyPassword";
my $db = "__x.xdb";

sub new_key {
  my $id;
  my ($name, $size, $type) = @_;
  print "name=$name, size=$size, Type=$type\n";
  SendKeys("%(n)");
  $id = WaitWindowViewable();
  SendKeys($name ."{TAB}" .$size ."{TAB}". $type ."{ENT}");
  WaitWindowClose($id, 100);
}

StartApp("./xca");
($xcaId) = WaitWindowViewable("X Certificate and Key management");
printf "XCA id: $xcaId\n";
SendKeys("%(fo)");
WaitWindowViewable("Open XCA Database");
SendKeys($db . "{ENT}");
WaitWindowViewable("Password");
SendKeys($password  ."{ENT}");

for ($i=0; $i<500; $i++) {
  my $len=int(rand(3200)) + 1024;
  new_key("rsa_key-$len", $len, "r");
  $len=int(rand(1500)) + 1024;
  new_key("dsa_key-$len", $len, "d");
  new_key("ec_key-$len", $len, "e");
}

SendKeys("%({F4})");
WaitWindowClose($xcaId, 10);

exec("lib/db_dump", $db);
