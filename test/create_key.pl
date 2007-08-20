#!/usr/bin/perl
use X11::GUITest qw/StartApp WaitWindowViewable SendKeys
	SetInputFocus WaitWindowClose GetInputFocus GetWindowName
	GetChildWindows/;

my $xcaId;
my $password = "ThisIsMyPassword";
my $db = "__x.xdb";
#unlink $db;

sub new_key {
  my $id;
  my ($name, $size, $type) = @_;
  print "name=$name, size=$size, Type=$type\n";
  SendKeys("%(n)");
  $id = WaitWindowViewable("New key");
  SendKeys($name ."{TAB}" .$size ."{TAB}". $type ."{ENT}");
  WaitWindowClose($id, 10);
}

StartApp("./xca $db");
($xcaId) = WaitWindowViewable("X Certificate and Key management");
printf "XCA id: $xcaId\n";
WaitWindowViewable("Password");
SendKeys($password  ."\n");

for ($i=0; $i<500; $i++) {
  my $len=int(rand(3200)) + 800;
  new_key("rsa_key-$len", $len, "r");
  $len=int(rand(1500)) + 500;
  new_key("dsa_key-$len", $len, "d");
}

SendKeys("%({F4})");
WaitWindowClose($xcaId, 10);

exec("lib/db_dump", $db);
