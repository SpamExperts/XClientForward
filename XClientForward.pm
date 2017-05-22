# <@LICENSE>
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to you under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# </@LICENSE>

=head1 NAME

Mail::SpamAssassin::Plugin::XClientForward - Use an outside mail filtering

=head1 SYNOPSIS

  loadplugin     Mail::SpamAssassin::Plugin::XClientForward

=head1 DESCRIPTION

XClientForward is a method to use an email filtering system forwarding the
message to an outside mx server using swaks and passing xclient details.

=cut


package Mail::SpamAssassin::Plugin::XClientForward;

use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Logger;
use Mail::SpamAssassin::Timeout;
use Mail::SpamAssassin::Util qw(untaint_var untaint_file_path
                                proc_status_ok exit_status_str);

use strict;
use warnings;
use bytes;
use re 'taint';

use vars qw(@ISA);
@ISA = qw(Mail::SpamAssassin::Plugin); # Inherits the PLUGIN

# Constructor
# Register the eval rule
sub new {
  my $class = shift;
  my $mailsaobject = shift;

  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsaobject);
  bless ($self, $class);

  $self->register_eval_rule("check_spamfilter");

  $self->set_config($mailsaobject->{conf});

  return $self;
}

sub set_config{
  my ($self, $conf) = @_;
  my @cmds;

=head1 USER OPTIONS

=over 4

=item use_swaks (0|1)   (default: 1)

  Wheter to use swaks, if it is available.

=cut

  push (@cmds, {
          setting => 'use_swaks',
          default => 1,
          type => $Mail::SpamAssassin::Conf::CONF_TYPE_BOOL
      });

=back

=head1 ADMINISTRATOR OPTIONS

=over 4

=item swaks_timeout n   (default: 60)

  How many seconds you want for Swaks to complete, before scanning continues
  without the outside mx server results.

=cut

  push (@cmds, {
          setting => 'swaks_timeout',
          is_admin => 1,
          default => 60,
          type => $Mail::SpamAssassin::Conf::CONF_TYPE_DURATION
      });

=item swaks_options options

Specify additional options to the swaks(1) command. Please note that only
characters in the range [0-9A-Za-z ,._/-] are allowed for security reasons.

=cut

    push (@cmds, {
            setting => 'swaks_options',
            is_admin => 1,
            default => '',
            type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
            code => sub {
                my ($self, $key, $value, $line) = @_;
                if ($value !~ m{^([0-9A-Za-z ,._/-]+)$}) {
                    return $Mail::SpamAssassin::Conf::INVALID_VALUE;
                }
                $self->{swaks_options} = $1;
            }
        });

=item swaks_path STRING

  This option tells SpamAssassin specifically where to find the C<swaks>
  client instead of relying on SpamAssassin to find it in the current PATH.
  Note that if I<taint mode> is enabled in the Perl interpreter,
  you should use this, as the current PATH will have been cleared.

=cut

  push (@cmds, {
          setting => 'swaks_path',
          is_admin => 1,
          default => undef,
          type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
          code => sub {
            my ($self, $key, $value, $line) = @_;
            if (!defined $value || !length $value) {
              return $Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE;
            }
            $value = untaint_file_path($value);
            if (!-x $value) {
              info("config: swaks_path \"$value\" isn't an executable");
              return $Mail::SpamAssassin::Conf::INVALID_VALUE;
            }

            $self->{swaks_path} = $value;
          }
      });

    $conf->{parser}->register_commands(\@cmds);
}


sub is_swaks_available {
  my ($self) = @_;

  my $swaks = $self->{main}->{conf}->{swaks_path} || '';
  unless ($swaks) {
    $swaks = Mail::SpamAssassin::Util::find_executable_in_env_path('swaks');
  }
  unless ($swaks && -x $swaks) {
    dbg("xclientforward: swaks is not available: no swaks executable found");
    return 0;
  }

  # remember any found swaks
  $self->{main}->{conf}->{swaks_path} = $swaks;

  dbg("xclientforward: swaks is available: " . $self->{main}->{conf}->{swaks_path});
  return 1;
}

sub get_swaks_interface {
  my ($self) = @_;

  if (!$self->{main}->{conf}->{use_swaks}) {
    dbg("xclientforward: use_swaks option not enabled, disabling XClientForward Plugin");
    $self->{swaks_interface} = "disabled";
    $self->{swaks_available} = 0;
  }
  elsif ($self->is_swaks_available()) {
    $self->{swaks_interface} = "swaks";
    $self->{swaks_available} = 1;
  }
  else {
    dbg("xclientforward: no swaks found, disabling XClientForward Plugin");
    $self->{swaks_available} = 0;
  }
}

sub get_xclient_vars {
    my ($self, $pms) = @_;

    # Take the most recent trusted relay
    my $rcvd = $pms->{relays_trusted}->[0];

    # If it doesn't exist take the most recent untrusted relay
    unless (defined $rcvd){
        $rcvd = $pms->{relays_untrusted}->[0];
    }

    # If $rcvd isn't defined means that we have no relays
    # form where to extract needed xclient vars
    return 0 unless (defined $rcvd);
    my $xclient_addr = $rcvd->{ip};
    my $xclient_helo = $rcvd->{helo};
    my $xclient_name = $rcvd->{rdns};
    my $envfrom = $rcvd->{envfrom};
    return 0 unless (defined $xclient_addr and defined $xclient_helo and defined $xclient_name);
    $pms->{xclient_addr} = $xclient_addr;
    $pms->{xclient_helo} = $xclient_helo;
    $pms->{xclient_name} = $xclient_name;
    $pms->{envelope_from} = $envfrom;
    $pms->{xclient_info} = 1;
    return 1;
}

sub check_spamfilter {
    my ($self, $permsgstatus, $full, $recipient, $server, $port) = @_;

    # initialize valid tags
    $permsgstatus->{tag_data}->{XCLIENTFORWARD} = "";
    my $timer = $self->{main}->time_method("check_spamfilter");
    $self->get_swaks_interface();
    return 0 unless $self->{swaks_available};
    $permsgstatus->{xclient_info} = 0;
    $self->get_xclient_vars($permsgstatus);

    return $self->spamfilter_lookup($permsgstatus, $full, $recipient, $server, $port);
}

sub spamfilter_lookup {
    my ($self, $permsgstatus, $fulltext, $recipient, $server, $port) = @_;
    my @response;
    my $timeout = $self->{main}->{conf}->{swaks_timeout};
    my $pid;

    # use a temp file here -- open2() is unreliable, buffering-wise, under spamd
    my $tmpf = $permsgstatus->create_fulltext_tmpfile($fulltext);

    # note: not really tainted, this came from system configuration file
    my $path = untaint_file_path($self->{main}->{conf}->{swaks_path});
    my $from_header = $permsgstatus->{msg}->{headers}->{from};
    my $from_header_addr = $permsgstatus->get("From:addr");

    $permsgstatus->enter_helper_run_mode();

    # Load the default options
    my @opts = split(' ', untaint_var("-n -t $recipient -s $server:$port --data $tmpf"));

    # Load the options form config
    my $config_opts = untaint_var($self->{main}->{conf}->{swaks_options});
    if ($config_opts){
        push(@opts, split(' ', $config_opts));
    }
    if ($permsgstatus->{xclient_info}){
        my $xclient_opt = untaint_var("--xclient \"name=$permsgstatus->{xclient_name}
        ADDR=$permsgstatus->{xclient_addr}\" --ehlo $permsgstatus->{xclient_helo}");
        push(@opts, split(' ', $xclient_opt));
    }


    if ($permsgstatus->{envelope_from}){
        push(@opts, split(' ', untaint_var("-f $permsgstatus->{envelope_from}")));
    }
    else{
        push(@opts, split(' ', untaint_var("-f $from_header_addr")));
    }
    if ($from_header){
        $from_header = "$from_header->[0]";
        push(@opts, split(' ', untaint_var("-h-From \"$from_header\"")));
    }

    my $timer = Mail::SpamAssassin::Timeout->new(
        { secs => $timeout, deadline => $permsgstatus->{master_deadline} });

    my $err = $timer->run_and_catch(sub {

        local $SIG{PIPE} = sub { die "__brokenpipe__ignore__\n" };

        dbg("xclientforward: opening pipe: " . join(' ', $path, @opts));

        $pid = Mail::SpamAssassin::Util::helper_app_pipe_open(*SWAKS,
            "/dev/null", 1, $path, @opts);
        $pid or die "$!\n";

        # read+split avoids a Perl I/O bug (Bug 5985)
        my($inbuf,$nread,$resp); $resp = '';
        while ( $nread=read(SWAKS,$inbuf,8192) ) { $resp .= $inbuf }
        defined $nread  or die "error reading from pipe: $!";
        @response = split(/^/m, $resp, -1);  undef $resp;

        my $errno = 0;  close SWAKS or $errno = $!;
        if (proc_status_ok($?,$errno)) {
            dbg("xclientforward: [%s] finished successfully", $pid);
        } elsif (proc_status_ok($?,$errno, 0,1)) {  # sometimes it exits with 1
            dbg("xclientforward: [%s] finished: %s", $pid, exit_status_str($?,$errno));
        } else {
            info("xclientforward: [%s] error: %s", $pid, exit_status_str($?,$errno));
        }

        if (!@response) {
            # this exact string is needed below
            die("no response\n");	# yes, this is possible
        }
        chomp for @response;
        dbg("xclientforward: got response: " . join("\\n", @response));

    });

    if (defined(fileno(*SWAKS))) {  # still open
        if ($pid) {
            if (kill('TERM',$pid)) { dbg("xclientforward: killed stale helper [$pid]") }
            else { dbg("xclientforward: killing helper application [$pid] failed: $!") }
        }
        my $errno = 0;  close SWAKS or $errno = $!;
        proc_status_ok($?,$errno)
            or info("xclientforward: [%s] error: %s", $pid, exit_status_str($?,$errno));
    }

    if ($timer->timed_out()) {
        dbg("xclientforward: check timed out after $timeout seconds");
        return 0;
    }

    if ($err) {
        chomp $err;
        if ($err eq "__brokenpipe__ignore__") {
            dbg("xclientforward: check failed: broken pipe");
        } elsif ($err eq "no response") {
            dbg("xclientforward: check failed: no response");
        } else {
            warn("xclientforward: check failed: $err\n");
        }
        return 0;
    }

    my $raw_response = join("\\n", @response);


    if ($raw_response =~ /\<\-\s+250\sOK\sid=(\w+\-\w+\-\w+)/i){
        # Mesage was accepted
        my $exim_id = $1;
        if (defined $exim_id) {
            dbg("xclientforward: Message with exim-id: $exim_id is NOT SPAM");
            return 0;
        }
    }
    if ($raw_response =~ /\<\*\*\s550(?:\s|-)(.+?(?=\\n))/) {
        # Message was rejected
        my $error_message = $1;
        if ($error_message =~ /\Qrelay not permitted\E/){
            dbg("xclientforward: Message is NOT considered spam: $error_message");
            return 0;
        }
        if ($error_message =~ /\Qhas no A, AAAA, or MX DNS records\E/ ||
            $error_message =~ /\Qno mailbox by that name is currently available\E/){
            dbg("xclientforward: Error occured when tried to send the message: $error_message");
            return 0;
        }
        dbg("xclientforward: Message is SPAM: $error_message");
        return 1;
    }
    dbg("xclientforward: Unsure Response");
    return 0;
}

1;
