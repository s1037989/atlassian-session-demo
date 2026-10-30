#!/usr/bin/env perl
use Mojolicious::Lite -signatures;
use Digest::SHA qw(sha256);
use MIME::Base64 qw(encode_base64url);
use Scalar::Util qw(refaddr);
use Mojo::URL;
use Mojo::Promise;

# Unix demo: cryptographic randomness, with no dependency beyond Mojolicious.
sub random_token {
  open my $fh, '<:raw', '/dev/urandom' or die 'Cannot open OS random source';
  my $bytes = '';
  while (length($bytes) < 32) {
    my $n = read $fh, my $part, 32 - length($bytes);
    die 'Cannot read OS random source' unless $n;
    $bytes .= $part;
  }
  return encode_base64url($bytes);
}

my $base = $ENV{APP_BASE_URL} // 'https://localhost:3000';
$base =~ s{/$}{};
my $http_test = $ENV{ALLOW_LOOPBACK_HTTP} // 0;
sub checked_url ($value) {
  my $u = Mojo::URL->new($value);
  die 'Use an absolute HTTPS URL (no query, fragment, or credentials)'
    unless $u->host && !$u->userinfo && !$u->query->to_string && !$u->fragment
      && ($u->scheme eq 'https' || ($http_test && $u->scheme eq 'http'
        && $u->host =~ /\A(?:127\.0\.0\.1|localhost|::1)\z/));
  return $u;
}
checked_url($base);
die 'APP_BASE_URL must have no path prefix' if Mojo::URL->new($base)->path->to_string !~ m{\A/?\z};
my $secret = $ENV{SESSION_SECRET} // random_token();
die 'SESSION_SECRET must contain at least 32 characters' if length($secret) < 32;
app->secrets([$secret]);
app->log->level('info'); # Do not enable HTTP/body tracing for OAuth traffic.
app->sessions->cookie_name('atlassian_demo');
app->sessions->default_expiration(0); # Browser-session cookie, not a persistent cookie.
app->sessions->samesite('Lax');       # Allows the top-level OAuth callback GET.
app->sessions->secure(Mojo::URL->new($base)->scheme eq 'https' ? 1 : 0);

my %products;
for my $name (qw(jira confluence)) {
  my $prefix = uc $name;
  my $url = $ENV{"${prefix}_BASE_URL"} // "https://$name.example.internal";
  $url =~ s{/$}{};
  checked_url($url);
  $products{$name} = {
    name => ucfirst($name), base => $url,
    client_id => $ENV{"${prefix}_CLIENT_ID"} // '',
    client_secret => $ENV{"${prefix}_CLIENT_SECRET"} // '',
    redirect_uri => "$base/oauth/$name/callback",
    scope => 'READ',
    profile_path => $name eq 'jira' ? '/rest/api/2/myself' : '/rest/api/user/current',
  };
}

# Each process owns its own store. Run this demo with the single-process daemon.
# Cookie contains only sid; OAuth credentials NEVER go in $c->session(...).
my %sessions;
my $idle_seconds = $ENV{SESSION_IDLE_SECONDS} // 1800;
my $max_seconds  = $ENV{SESSION_MAX_SECONDS} // 28800;
die 'Invalid session timeouts' unless $idle_seconds =~ /\A[1-9][0-9]*\z/
  && $max_seconds =~ /\A[1-9][0-9]*\z/;
sub live ($ss) { $ss && $ss->{active} && time < $ss->{idle_until} && time < $ss->{ends_at} }
Mojo::IOLoop->recurring(60 => sub {
  for my $sid (keys %sessions) {
    next if live($sessions{$sid});
    $sessions{$sid}{active} = 0;
    delete $sessions{$sid};
  }
});

hook before_dispatch => sub ($c) {
  my $sid = $c->session('sid') // '';
  my $ss = $sessions{$sid};
  if (!live($ss)) {
    $ss->{active} = 0 if $ss;
    delete $sessions{$sid};
    $sid = random_token();
    $ss = $sessions{$sid} = {
      active => 1, csrf => random_token(), connections => {},
      idle_until => time + $idle_seconds, ends_at => time + $max_seconds,
    };
    $c->session({sid => $sid});
  }
  $ss->{idle_until} = time + $idle_seconds;
  $c->stash(ss => $ss, sid => $sid);
};
hook after_dispatch => sub ($c) {
  $c->res->headers->cache_control('no-store');
  $c->res->headers->header('Referrer-Policy' => 'no-referrer');
  $c->res->headers->header('X-Content-Type-Options' => 'nosniff');
  $c->res->headers->header('Content-Security-Policy' => "default-src 'self'; style-src 'unsafe-inline'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'");
};

# This dedicated UA has no shared user credentials/cookies or redirect following.
my $api_ua = Mojo::UserAgent->new->request_timeout(20)->max_redirects(0);
$api_ua->cookie_jar->ignore(sub { 1 });
helper api_ua => sub { $api_ua };
helper product => sub ($c, $name) { $products{$name} };
helper csrf_ok => sub ($c) {
  return 1 if ($c->param('csrf') // '') eq $c->stash('ss')->{csrf};
  $c->render(status => 403, text => 'Invalid CSRF token. Reload the home page.');
  return 0;
};
helper connection_current => sub ($c, $name, $conn) {
  my $ss = $c->stash('ss');
  my $current = $ss->{connections}{$name};
  return live($ss) && $current && refaddr($current) == refaddr($conn);
};

# Tokens travel in the form body, never in token endpoint query strings.
helper token_request_p => sub ($c, $name, $form) {
  my $p = $products{$name};
  return $api_ua->post_p("$p->{base}/rest/oauth2/latest/token" =>
    {Accept => 'application/json'} => form => {
      %$form, client_id => $p->{client_id}, client_secret => $p->{client_secret},
      redirect_uri => $p->{redirect_uri},
    })->then(sub ($tx) {
      my $r = $tx->result;
      my $data = $r->json;
      die 'token_exchange_failed' unless $r->is_success && ref($data) eq 'HASH'
        && ($data->{access_token} // '') ne '' && ($data->{refresh_token} // '') ne ''
        && ($data->{expires_in} // '') =~ /\A[1-9][0-9]*\z/;
      return {access => $data->{access_token}, refresh => $data->{refresh_token},
        expires_at => time + $data->{expires_in}};
    });
};

helper access_token_p => sub ($c, $name, $conn) {
  return Mojo::Promise->reject('not_connected')
    unless $c->connection_current($name, $conn) && $conn->{tokens};
  my $t = $conn->{tokens};
  return Mojo::Promise->resolve($t->{access}) if $t->{expires_at} > time + 30;
  # All requests for this session/product await one refresh. Other users have
  # different $conn objects, and Jira/Confluence have different objects too.
  return $conn->{refreshing} if $conn->{refreshing};
  $conn->{refreshing} = $c->token_request_p($name, {
    grant_type => 'refresh_token', refresh_token => $t->{refresh},
  })->then(sub ($new) {
    die 'session_ended' unless $c->connection_current($name, $conn);
    $conn->{tokens} = $new; # Replace access AND refresh token together.
    return $new->{access};
  })->finally(sub { delete $conn->{refreshing}; return; });
  return $conn->{refreshing};
};

get '/' => sub ($c) {
  $c->stash(products => \%products);
  $c->render(template => 'home');
};

post '/connect/:provider' => sub ($c) {
  my $name = $c->param('provider');
  my $p = $c->product($name) or return $c->reply->not_found;
  return unless $c->csrf_ok;
  return $c->render(status => 503, text => 'Configure the product client ID and secret first.')
    unless $p->{client_id} && $p->{client_secret};
  my $pending = {state => random_token(), verifier => random_token(), started => time};
  $c->stash('ss')->{connections}{$name} = {pending => $pending};
  my $url = Mojo::URL->new("$p->{base}/rest/oauth2/latest/authorize")->query({
    client_id => $p->{client_id}, redirect_uri => $p->{redirect_uri},
    response_type => 'code', scope => $p->{scope}, state => $pending->{state},
    code_challenge => encode_base64url(sha256($pending->{verifier})),
    code_challenge_method => 'S256',
  });
  $c->redirect_to($url);
};

get '/oauth/:provider/callback' => sub ($c) {
  my $name = $c->param('provider');
  return $c->reply->not_found unless $c->product($name);
  my $conn = $c->stash('ss')->{connections}{$name};
  my $pending = $conn && $conn->{pending};
  return $c->render(status => 400, text => 'Invalid or expired OAuth state. Start the connection again.')
    unless $pending && time - $pending->{started} < 600
      && ($c->param('state') // '') eq $pending->{state};
  delete $conn->{pending}; # Single use, including denial and failed exchanges.
  return $c->render(status => 400, text => 'Authorization was declined. You may try connecting again.')
    if $c->param('error');
  my $code = $c->param('code');
  return $c->render(status => 400, text => 'Missing authorization code.') unless $code;
  $c->render_later;
  $c->token_request_p($name, {grant_type => 'authorization_code', code => $code,
    code_verifier => $pending->{verifier}})->then(sub ($tokens) {
      die 'session_ended' unless $c->connection_current($name, $conn);
      $conn->{tokens} = $tokens;
      $c->redirect_to('/');
    })->catch(sub ($error) {
      $c->render(status => 502, text => 'Connection failed. Start the connection again.');
    });
};

# A small real API example for each product: show the connected user's profile.
get '/api/:provider/me' => sub ($c) {
  my $name = $c->param('provider');
  my $p = $c->product($name) or return $c->reply->not_found;
  my $conn = $c->stash('ss')->{connections}{$name};
  return $c->render(status => 401, json => {error => 'Connect this product first.'})
    unless $conn && $conn->{tokens};
  $c->render_later;
  $c->access_token_p($name, $conn)->then(sub ($token) {
    die 'session_ended' unless $c->connection_current($name, $conn);
    # Pass THIS session's bearer on THIS request; never set a UA-wide bearer.
    return $api_ua->get_p("$p->{base}$p->{profile_path}" => {
      Accept => 'application/json', Authorization => "Bearer $token",
    });
  })->then(sub ($tx) {
    die 'session_ended' unless $c->connection_current($name, $conn);
    my $res = $tx->result;
    if (($res->code // 0) == 401) {
      delete $conn->{tokens};
      return $c->render(status => 401, json => {error => 'Authorization expired or was revoked. Reconnect.'});
    }
    return $c->render(status => 403, json => {error => 'The product denied access to this user.'})
      if ($res->code // 0) == 403;
    die 'upstream_failed' unless $res->is_success && defined $res->json;
    $c->render(json => $res->json);
  })->catch(sub ($error) {
    # Avoid returning/logging upstream bodies, codes, tokens, or exception text.
    $c->render(status => 502, json => {error => 'Unable to use this connection. Retry or reconnect.'});
  });
};

post '/disconnect/:provider' => sub ($c) {
  my $name = $c->param('provider');
  return $c->reply->not_found unless $c->product($name);
  return unless $c->csrf_ok;
  delete $c->stash('ss')->{connections}{$name};
  $c->redirect_to('/');
};
post '/logout' => sub ($c) {
  return unless $c->csrf_ok;
  $c->stash('ss')->{active} = 0;
  delete $sessions{$c->stash('sid')};
  $c->session(expires => 1);
  $c->redirect_to('/');
};

app->start;
__DATA__
@@ home.html.ep
<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Atlassian connections</title>
<style>
body{font:17px/1.5 system-ui,sans-serif;background:#f4f6fa;color:#172b4d;margin:0}main{max-width:850px;margin:64px auto;padding:24px}h1{font-size:36px;letter-spacing:-1px;margin:0}.intro{color:#52617b}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:20px;margin:30px 0}.card{background:white;padding:28px;border:1px solid #dce3ef;border-radius:14px}h2{margin:0 0 12px}.status{font-size:14px;color:#52617b}.connected{color:#176845}button,.button{font:inherit;background:#0c66e4;color:white;border:0;border-radius:6px;padding:9px 15px;cursor:pointer;text-decoration:none;display:inline-block}form{margin-top:18px}.secondary{background:#e9edf5;color:#172b4d}.note{font-size:14px;color:#52617b}code{font-size:13px;overflow-wrap:anywhere}
</style></head>
<body><main><h1>Atlassian connections</h1>
<p class="intro">Connect your own Jira and Confluence accounts. Each connection belongs to this browser session.</p>
<div class="cards">
% for my $name (qw(jira confluence)) {
% my $p = $products->{$name};
% my $connected = !!$ss->{connections}{$name}{tokens};
<section class="card"><h2><%= $p->{name} %></h2>
<p class="status <%= $connected ? 'connected' : '' %>"><%= $connected ? 'Connected for this session' : 'No account connected' %></p>
<p class="note"><%= $p->{base} %></p>
% if ($connected) {
<a class="button" href="/api/<%= $name %>/me">View my profile JSON</a>
<form method="post" action="/disconnect/<%= $name %>"><input type="hidden" name="csrf" value="<%= $ss->{csrf} %>"><button class="secondary">Disconnect</button></form>
% } else {
<form method="post" action="/connect/<%= $name %>"><input type="hidden" name="csrf" value="<%= $ss->{csrf} %>"><button>Connect <%= $p->{name} %></button></form>
% }
</section>
% }
</div>
<p class="note">You sign in and approve access on the Jira or Confluence site. This app never asks for your password.</p>
<form method="post" action="/logout"><input type="hidden" name="csrf" value="<%= $ss->{csrf} %>"><button class="secondary">End session</button></form>
<p class="note">Connections are discarded after inactivity, at the maximum session lifetime, or when this demo restarts. Tabs in the same browser profile share a session.</p>
</main></body></html>
