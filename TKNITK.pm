package Mail::SpamAssassin::Plugin::TKNITK;

use strict;
use warnings;
use bytes;
use re 'taint';

use Digest::SHA qw(sha1 sha1_hex);

use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::PerMsgStatus;
use Mail::SpamAssassin::Logger;

our @ISA = qw(Mail::SpamAssassin::Plugin);

sub new {
        my $class = shift;
        my ($main) = @_;

        $class = ref($class) || $class;
        my $self = $class->SUPER::new($main);
        bless ($self, $class);

        $self->{main} = $main;
        $self->{conf} = $main->{conf};
        $self->{use_ignores} = 1;

        $self->register_eval_rule("msg_length");
        return $self;
}

sub msg_length {
                my($self, $pms) = @_;
                my $body = $pms->{msg}->{pristine_body};
		$pms->set_tag ("TK_TAG", "Debug TKNITK");
		my ($substr) = ($body =~/>(.*)\</);
		dbg($substr);
		#dbg($body);
		dbg("\n");
		my $max = 0;
		my %count;
		foreach my $str (split / /,$substr) {
		$count{$str}++;
		if($count{$str}>=$max)
		{	
			$max=$count{$str} ;
			if($max >=4){ dbg($str);return 1;} 
			#hits if a word repeats more than 4 times
		}
		#hits if a body is longer than 100 characters
                return (length $substr >=10)? 1 : 0;
}
