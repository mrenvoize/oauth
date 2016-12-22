package MyApp;
use Mojo::Base 'Mojolicious';

has db => sub {
    my $self         = shift;
    my $schema_class = 'MyApp::Schema';
    eval "require $schema_class"
      or die "Could not load Schema Class ($schema_class). $@\n";

    my $schema = $schema_class->connect(
        @{ $self->config }{qw/db_dsn db_username db_password db_options/} )
      or die "Could not connect to $schema_class using DSN "
      . $self->config->{db_dsn};

    return $schema;
};

sub startup {
    my $app = shift;

    # Helpers
    $app->helper( schema => sub { shift->app->db } );

    # Plugins
    $app->plugin(
        'OAuth2::Server' => {
            clients => {
                1 => {
                    client_secret => 'kaboom!',
                    scopes        => { eat => 1, drink => 0, sleep => 1 },
                },
            },
            jwt_secret => 'bingooom'
        }
    );

    # Router
    my $r = $app->routes;

    # Normal route to controller
    $r->get('/')->to('example#welcome');

    # Authentication Callbacks

    # confirm_by_resource_owner_cb
    # A coderef callback used for varifying if the `resource owner` has granted,
    # or denied, access to the `resource server` for the given `scopes` to the
    # given `client`.
    my $resource_owner_confirm_scopes_sub = sub {
        my (%args) = @_;

        my ( $c, $client_id, $scopes_ref, $redirect_uri, $response_type ) =
          @args{qw/ c client_id scopes redirect_uri response_type /};

        my $is_allowed = $c->flash("oauth_${client_id}");

        # if user hasn't yet allowed the client access, or if they denied
        # access last time, we check [again] with the user for access
        if ( !$is_allowed ) {
            $c->flash( client_id => $client_id );
            $c->flash( scopes    => $scopes_ref );

            # we need to redirect back to the /oauth/authorize route after
            # confirm/deny by resource owner (with the original params)
            my $uri = join( '?', $c->url_for('current'), $c->url_with->query );
            $c->flash( 'redirect_after_login' => $uri );
            $c->redirect_to('/oauth/confirm_scopes');
        }

        return $is_allowed;
    };

    # login_resource_owner_cb
    # A coderef callback used for varfiying whether the `resource owner`
    # is logged in or not
    my $resource_owner_logged_in_sub = sub {
        my (%args) = @_;

        my $c = $args{mojo_controller};

        if ( !$c->session('logged_in') ) {

            # we need to redirect back to the /oauth/authorize route after
            # login (with the original params)
            my $uri = join( '?', $c->url_for('current'), $c->url_with->query );
            $c->flash( 'redirect_after_login' => $uri );
            $c->redirect_to('/oauth/login');
            return 0;
        }

        return 1;
    };

    # varify_client_cb
    # A coderef callback used for varifying if the `client` asking for an auth
    # token is known by the `Resource Server` and allowed to make authorization
    # requests for the passed scopes
    my $varify_client_sub = sub {
        my (%args) = @_;

        my ( $c, $client_id, $scopes, $redirect_uri, $response_type,
            $client_secret )
          = @args{
            qw/c client_id scopes redirect_uri response_type client_secret/
          };

        if ( my $client = $c->db->resultset('APIClient')->find($client_id) ) {
            for my $scope ( keys %{$scopes} ) {
                if ( !exists( $client->scopes->{$scope} ) ) {
                    return ( 0, 'invalid_scope' );
                }
                elsif ( !$client->scopes->{$scope} ) {
                    return ( 0, 'access_denied' );
                }
            }

            return (1);
        }

        return ( 0, 'unauthorized_client' );
    };

    # store_auth_code_cb
    # A coderef for a callback to store generated authorization codes.
    my $store_auth_code_sub = sub {
        my (%args) = @_;

        my ( $obj, $auth_code, $client_id, $expires_in, $uri, $scopes_ref ) =
          @args{
            qw/ mojo_controller auth_code client_id expires_in redirect_uri scopes /
          };

        my $auth_codes = $obj->db->get_collection('auth_codes');

        my $id = $auth_codes->insert(
            {
                auth_code    => $auth_code,
                client_id    => $client_id,
                user_id      => $obj->session('user_id'),
                expires      => time + $expires_in,
                redirect_uri => $uri,
                scope        => { map { $_ => 1 } @{ $scopes_ref // [] } },
            }
        );

        return;
    };

    # varify_auth_code_cb
    # A coderef for a callback to varify the authorization code passed from the
    # `client` to the `authorization server`.
    my $verify_auth_code_sub = sub {
        my (%args) = @_;

        my ( $obj, $client_id, $client_secret, $auth_code, $uri ) =
          @args{
            qw/ mojo_controller client_id client_secret auth_code redirect_uri /
          };

        my $auth_codes = $obj->db->get_collection('auth_codes');
        my $ac         = $auth_codes->find_one(
            {
                client_id => $client_id,
                auth_code => $auth_code,
            }
        );

        my $client = $obj->db->get_collection('clients')
          ->find_one( { client_id => $client_id } );

        $client || return ( 0, 'unauthorized_client' );

        if (  !$ac
            or $ac->{verified}
            or ( $uri ne $ac->{redirect_uri} )
            or ( $ac->{expires} <= time )
            or ( $client_secret ne $client->{client_secret} ) )
        {

            if ( $ac->{verified} ) {

             # the auth code has been used before - we must revoke the auth code
             # and access tokens
                $auth_codes->remove( { auth_code => $auth_code } );
                $obj->db->get_collection('access_tokens')->remove(
                    {
                        access_token => $ac->{access_token}
                    }
                );
            }

            return ( 0, 'invalid_grant' );
        }

       # scopes are those that were requested in the authorization request, not
       # those stored in the client (i.e. what the auth request restriced scopes
       # to and not everything the client is capable of)
        my $scope = $ac->{scope};

        $auth_codes->update( $ac, { verified => 1 } );

        return ( $client_id, undef, $scope, $ac->{user_id} );
    };

# store_access_token_cb
# A coderef for a callback that will store any generated access and refresh tokens.
    my $store_access_token_sub = sub {
        my (%args) = @_;

        my ( $obj, $client, $auth_code, $access_token, $refresh_token,
            $expires_in, $scope, $old_refresh_token )
          = @args{
            qw/
              mojo_controller client_id auth_code access_token
              refresh_token expires_in scopes old_refresh_token
              /
          };

        my $access_tokens  = $obj->db->get_collection('access_tokens');
        my $refresh_tokens = $obj->db->get_collection('refresh_tokens');

        my $user_id;

        if ( !defined($auth_code) && $old_refresh_token ) {

       # must have generated an access token via refresh token so revoke the old
       # access token and refresh token (also copy required data if missing)
            my $prev_rt = $obj->db->get_collection('refresh_tokens')->find_one(
                {
                    refresh_token => $old_refresh_token,
                }
            );

            my $prev_at = $obj->db->get_collection('access_tokens')->find_one(
                {
                    access_token => $prev_rt->{access_token},
                }
            );

          # access tokens can be revoked, whilst refresh tokens can remain so we
          # need to get the data from the refresh token as the access token may
          # no longer exist at the point that the refresh token is used
            $scope //= $prev_rt->{scope};
            $user_id = $prev_rt->{user_id};

            # need to revoke the access token
            $obj->db->get_collection('access_tokens')
              ->remove( { access_token => $prev_at->{access_token} } );

        }
        else {
            $user_id = $obj->db->get_collection('auth_codes')->find_one(
                {
                    auth_code => $auth_code,
                }
            )->{user_id};
        }

        if ( ref($client) ) {
            $scope  = $client->{scope};
            $client = $client->{client_id};
        }

        # if the client has en existing refresh token we need to revoke it
        $refresh_tokens->remove(
            { client_id => $client, user_id => $user_id } );

        $access_tokens->insert(
            {
                access_token  => $access_token,
                scope         => $scope,
                expires       => time + $expires_in,
                refresh_token => $refresh_token,
                client_id     => $client,
                user_id       => $user_id,
            }
        );

        $refresh_tokens->insert(
            {
                refresh_token => $refresh_token,
                access_token  => $access_token,
                scope         => $scope,
                client_id     => $client,
                user_id       => $user_id,
            }
        );

        return;
    };

    # varify_access_token_cb
    # A coderef for a callback that will varify the access token.
    my $verify_access_token_sub = sub {
        my (%args) = @_;

        my ( $obj, $access_token, $scopes_ref, $is_refresh_token ) =
          @args{qw/ mojo_controller access_token scopes is_refresh_token /};

        my $rt = $obj->db->get_collection('refresh_tokens')->find_one(
            {
                refresh_token => $access_token
            }
        );

        if ( $is_refresh_token && $rt ) {

            if ($scopes_ref) {
                foreach my $scope ( @{ $scopes_ref // [] } ) {
                    if (   !exists( $rt->{scope}{$scope} )
                        or !$rt->{scope}{$scope} )
                    {
                        return ( 0, 'invalid_grant' );
                    }
                }
            }

            # $rt contains client_id, user_id, etc
            return $rt;
        }
        elsif (
            my $at = $obj->db->get_collection('access_tokens')->find_one(
                {
                    access_token => $access_token,
                }
            )
          )
        {

            if ( $at->{expires} <= time ) {

                # need to revoke the access token
                $obj->db->get_collection('access_tokens')
                  ->remove( { access_token => $access_token } );

                return ( 0, 'invalid_grant' );
            }
            elsif ($scopes_ref) {

                foreach my $scope ( @{ $scopes_ref // [] } ) {
                    if (   !exists( $at->{scope}{$scope} )
                        or !$at->{scope}{$scope} )
                    {
                        return ( 0, 'invalid_grant' );
                    }
                }

            }

            # $at contains client_id, user_id, etc
            return $at;
        }

        return ( 0, 'invalid_grant' );
    };

}

1;
