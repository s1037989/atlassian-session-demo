requires 'perl', '5.20.0';
requires 'Mojolicious', '9.40';
requires 'IO::Socket::SSL', '2.009';
on 'test' => sub { requires 'Test::More'; };
