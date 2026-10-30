use Mojo::Base -strict, -signatures;
use Test::More;
use Test::Mojo;
use Mojolicious;
use Mojo::URL;
use Mojo::Server;
use Mojo::Util qw(b64_decode);
use Mojo::JSON qw(decode_json);
use Digest::SHA qw(sha256);
use MIME::Base64 qw(encode_base64url);
use FindBin;

# Mock only the Atlassian HTTP boundary; exercise the real app and cookie jars.
my $mock = Mojolicious->new;
$mock->log->level('fatal');
my (%codes, %refreshes, %bearers, @forms);
my $serial = 0;
my $refresh_count = 0;
my $short_lived = 0;
my $reject_refresh = 0;
my $deny_api = 0;
my $mint = sub ($provider, $user, $seconds) {
  my $access = 'access-' . ++$serial;
  my $refresh = 'refresh-' . $serial;
  $bearers{$access} = {provider => $provider, user => $user};
  $refreshes{$refresh} = {provider => $provider, user => $user, access => $access};
  return {access_token => $access, refresh_token => $refresh,
    token_type => 'bearer', expires_in => $seconds};
};
$mock->routes->post('/:provider/rest/oauth2/latest/token')->to(cb => sub ($c) {
  my $p = $c->param('provider');
  my $form = $c->req->body_params->to_hash;
  push @forms, $form;
  is $c->req->url->query->to_string, '', 'No token or secret in URL query';
  is $form->{client_id}, "$p-client", 'Per-product client ID';
  is $form->{client_secret}, "$p-secret", 'Per-product client secret';
  is $form->{redirect_uri}, "http://127.0.0.1:3000/oauth/$p/callback", 'Registered callback';
  if ($form->{grant_type} eq 'authorization_code') {
    my $grant = delete $codes{$form->{code}};
    return $c->render(status => 400, json => {error => 'invalid_grant'}) unless $grant;
    is $p, $grant->{provider}, 'Code is bound to correct product';
    is encode_base64url(sha256($form->{code_verifier})), $grant->{challenge}, 'PKCE verifier matches challenge';
    return $c->render(json => $mint->($p, $grant->{user}, $short_lived ? 1 : 3600));
  }
  ++$refresh_count;
  return $c->render(status => 400, json => {error => 'invalid_grant'}) if $reject_refresh;
  my $grant = delete $refreshes{$form->{refresh_token}};
  return $c->render(status => 400, json => {error => 'invalid_grant'}) unless $grant;
  delete $bearers{$grant->{access}};
  is $p, $grant->{provider}, 'Refresh stays within product';
  # Async response makes concurrent refresh coalescing observable.
  $c->render_later;
  Mojo::IOLoop->timer(0.02 => sub { $c->render(json => $mint->($p, $grant->{user}, 3600)) });
});
$mock->routes->get('/:provider/*api_path')->to(cb => sub ($c) {
  my $token = $c->req->headers->authorization // '';
  $token =~ s/^Bearer //;
  my $who = $bearers{$token};
  return $c->render(status => 401, json => {error => 'invalid_token'})
    if $deny_api || !$who || $who->{provider} ne $c->param('provider');
  $c->render(json => {user => $who->{user}, product => $who->{provider}});
});
my $mock_client = Test::Mojo->new($mock);
my $mock_base = $mock_client->ua->server->url->to_string;
$mock_base =~ s{/$}{};
local $ENV{ALLOW_LOOPBACK_HTTP} = 1;
local $ENV{APP_BASE_URL} = 'http://127.0.0.1:3000';
local $ENV{SESSION_SECRET} = 'test-only-cookie-signing-secret-123456789';
for my $p (qw(jira confluence)) {
  $ENV{uc($p) . '_BASE_URL'} = "$mock_base/$p";
  $ENV{uc($p) . '_CLIENT_ID'} = "$p-client";
  $ENV{uc($p) . '_CLIENT_SECRET'} = "$p-secret";
}
my $app = Mojo::Server->new->load_app("$FindBin::Bin/../app.pl");
$app->log->level('fatal');
my $alice = Test::Mojo->new($app);
my $bob = Test::Mojo->new($app);
sub csrf ($t) {
  $t->get_ok('/')->status_is(200);
  return $t->tx->res->dom->at('input[name=csrf]')->attr('value');
}
sub begin_connection ($t, $p) {
  $t->post_ok("/connect/$p" => form => {csrf => csrf($t)})->status_is(302);
  my $url = Mojo::URL->new($t->tx->res->headers->location);
  is $url->path->to_string, "/$p/rest/oauth2/latest/authorize", 'Context path is retained';
  is $url->query->param('scope'), 'READ', 'Read-only scope';
  is $url->query->param('code_challenge_method'), 'S256', 'SHA-256 PKCE';
  return $url;
}
sub complete ($t, $p, $user, $url) {
  my $code = 'code-' . ++$serial;
  $codes{$code} = {user => $user, provider => $p, challenge => $url->query->param('code_challenge')};
  my $callback = Mojo::URL->new("/oauth/$p/callback")->query(
    code => $code, state => $url->query->param('state'));
  $t->get_ok($callback)->status_is(302)->header_is(Location => '/');
  return $callback;
}
sub connect_as ($t, $p, $user) { complete($t, $p, $user, begin_connection($t, $p)) }

$alice->get_ok('/api/jira/me')->status_is(401);
$alice->post_ok('/connect/jira' => form => {csrf => 'wrong'})->status_is(403);
my $url = begin_connection($alice, 'jira');
$bob->get_ok(Mojo::URL->new('/oauth/jira/callback')->query(state => $url->query->param('state'), code => 'stolen'))
  ->status_is(400);
$alice->get_ok('/oauth/jira/callback?state=wrong&code=wrong')->status_is(400);
my $callback = complete($alice, 'jira', 'alice', $url);
$alice->get_ok($callback)->status_is(400); # One-time state/code consumption.
connect_as($bob, 'jira', 'bob');
connect_as($alice, 'confluence', 'alice-wiki');
for my $t ($alice, $bob) {
  $t->get_ok('/api/jira/me')->status_is(200)
    ->json_is('/user', $t == $alice ? 'alice' : 'bob')->json_is('/product', 'jira');
}
$alice->get_ok('/api/confluence/me')->status_is(200)->json_is('/user', 'alice-wiki');
$bob->get_ok('/api/confluence/me')->status_is(401);
$alice->get_ok('/')->status_is(200)->header_is('Cache-Control' => 'no-store');
my ($cookie) = $alice->ua->cookie_jar->all->@*;
my ($payload) = split /--/, $cookie->value;
my $decoded = decode_json(b64_decode($payload));
is_deeply [sort keys %$decoded], ['sid'], 'Cookie payload contains only the opaque session ID';
unlike $alice->tx->res->body, qr/access-\d|refresh-\d|jira-secret/, 'Home page never contains credentials';

# Short expiry causes a refresh without a sleep. Two requests share one refresh.
$short_lived = 1;
connect_as($alice, 'jira', 'alice');
$short_lived = 0;
my $before = $refresh_count;
my $local_url = $alice->ua->server->url->clone->path('/api/jira/me');
my @responses;
Mojo::Promise->all(map {
  $alice->ua->get_p($local_url)->then(sub ($tx) { push @responses, $tx->result->json->{user} })
} 1..2)->wait;
is_deeply \@responses, ['alice', 'alice'], 'Concurrent requests use the correct refreshed connection';
is $refresh_count, $before + 1, 'Exactly one concurrent refresh';
$alice->get_ok('/api/jira/me')->status_is(200)->json_is('/user', 'alice');
$bob->get_ok('/api/jira/me')->status_is(200)->json_is('/user', 'bob');

$deny_api = 1;
$alice->get_ok('/api/jira/me')->status_is(401);
$deny_api = 0;
$alice->get_ok('/api/jira/me')->status_is(401);
$short_lived = 1;
connect_as($alice, 'jira', 'alice');
$short_lived = 0;
$reject_refresh = 1;
$alice->get_ok('/api/jira/me')->status_is(502)->content_unlike(qr/invalid_grant|refresh-\d/);
$reject_refresh = 0;

my $denied = begin_connection($bob, 'confluence');
$bob->get_ok(Mojo::URL->new('/oauth/confluence/callback')->query(
  state => $denied->query->param('state'), error => 'access_denied'))->status_is(400);
$bob->get_ok('/api/confluence/me')->status_is(401);
$alice->post_ok('/disconnect/confluence' => form => {csrf => csrf($alice)})->status_is(302);
$alice->get_ok('/api/confluence/me')->status_is(401);
my $old_cookie = $bob->ua->cookie_jar->all->[0]->value;
$bob->post_ok('/logout' => form => {csrf => csrf($bob)})->status_is(302);
# Replaying a former signed cookie after logout cannot restore the server record.
my $replay = Test::Mojo->new($app);
$replay->get_ok('/api/jira/me' => {Cookie => "atlassian_demo=$old_cookie"})->status_is(401);
$bob->get_ok('/api/jira/me')->status_is(401);
done_testing;
