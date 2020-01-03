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
		dbg($body);
                return (length $substr >=10)? 1 : 0;
}

