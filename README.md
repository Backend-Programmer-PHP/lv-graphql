# GraphQL-Laravel
Tiim hiểu QraphQL và Xác thực Token
composer require nuwave/lighthouse laravel/passport joselfonseca/lighthouse-graphql-passport-auth
Now let’s configure each of the packages starting with Laravel Passport, for that we are going to first run the migrations.
php artisan migrate


Then we should run the passport Install command.
php artisan passport:install


Then add the HasApiTokens trait to your user model

namespace App;

use Laravel\Passport\HasApiTokens;
use Illuminate\Notifications\Notifiable;
use Illuminate\Foundation\Auth\User as Authenticatable;

class User extends Authenticatable
{
    use HasApiTokens, Notifiable;
}
Now we should register the passport routes as we still need them to be able to get tokens internally.
namespace App\Providers;

use Laravel\Passport\Passport;
use Illuminate\Support\Facades\Gate;
use Illuminate\Foundation\Support\Providers\AuthServiceProvider as ServiceProvider;

class AuthServiceProvider extends ServiceProvider
{
    /**
     * The policy mappings for the application.
     *
     * @var array
     */
    protected $policies = [
        'App\Model' => 'App\Policies\ModelPolicy',
    ];
    /**
     * Register any authentication / authorization services.
     *
     * @return void
     */
    public function boot()
    {
        $this->registerPolicies();
        Passport::routes();
    }
}
Once we have this let’s add the passport driver to the API guard in the config/auth.php file.
'guards' => [
    'web' => [
        'driver' => 'session',
        'provider' => 'users',
    ],
    'api' => [
        'driver' => 'passport',
        'provider' => 'users',
    ],
],
This should conclude the passport configuration.

Now let’s configure and install the Lighthouse PHP package. since it was already pulled from composer we just need to run the following commands to publish the default schema.
php artisan vendor:publish --provider="Nuwave\Lighthouse\LighthouseServiceProvider" --tag=schema
This command will create a file in graphql/schema.graphql with the following schema
"A datetime string with format `Y-m-d H:i:s`, e.g. `2018-01-01 13:00:00`."
scalar DateTime @scalar(class: "Nuwave\\Lighthouse\\Schema\\Types\\Scalars\\DateTime")

"A date string with format `Y-m-d`, e.g. `2011-05-23`."
scalar Date @scalar(class: "Nuwave\\Lighthouse\\Schema\\Types\\Scalars\\Date")

type Query {
    users: [User!]! @paginate(type: "paginator" model: "App\\User")
    user(id: ID @eq): User @find(model: "App\\User")
}
type User {
    id: ID!
    name: String!
    email: String!
    created_at: DateTime!
    updated_at: DateTime!
}
If you have this file you should be ready to continue with the Lighthouse GraphQL Passport Auth package.

To get the values you need to open your database client and grab the password oauth client from the oauth_clients table, get the client id and secret and put them in the .env file
PASSPORT_CLIENT_ID=2
PASSPORT_CLIENT_SECRET=69YJomGV9plchWIkGD2PyKBBTHfkNA7H83iYGc6j
Once you do that, publish the package configuration and default schema.
php artisan vendor:publish --provider="Joselfonseca\LighthouseGraphQLPassport\Providers\LighthouseGraphQLPassportServiceProvider"
This command should publish 2 files, the config/lighthouse-graphql-passport.php and graphql/auth.graphql file. For convenience and to be able to have better control over the auth schema lets update the config file to use the published schema by changing the value for the schema property to the path to the published file like this:
'schema' => base_path('graphql/auth.graphql')
This will allow us to manipulate the schema if we need to extend it or make changes to the resolvers.

Now let’s remove the user type from the auth schema since we already have it in the default one exported before. Go to the graphql/auth/graphql file and remove the following type
type User {
    id: ID!
    name: String!
    email: String!
}
Once we do that, we need to add a default mutation to the schema so the auth can extend it or we can simply move the auth mutations to the Mutation type in the main schema file. So look for this code in the graphql/auth.graphql file and move it to graphql/schema.graphql file
extend type Mutation {
    login(input: LoginInput @spread): AuthPayload! @field(resolver: "Joselfonseca\\LighthouseGraphQLPassport\\GraphQL\\Mutations\\Login@resolve")
    refreshToken(input: RefreshTokenInput @spread): RefreshTokenPayload! @field(resolver: "Joselfonseca\\LighthouseGraphQLPassport\\GraphQL\\Mutations\\RefreshToken@resolve")
    logout: LogoutResponse! @field(resolver: "Joselfonseca\\LighthouseGraphQLPassport\\GraphQL\\Mutations\\Logout@resolve")
    forgotPassword(input: ForgotPasswordInput! @spread): ForgotPasswordResponse! @field(resolver: "Joselfonseca\\LighthouseGraphQLPassport\\GraphQL\\Mutations\\ForgotPassword@resolve")
    updateForgottenPassword(input: NewPasswordWithCodeInput @spread): ForgotPasswordResponse! @field(resolver: "Joselfonseca\\LighthouseGraphQLPassport\\GraphQL\\Mutations\\ResetPassword@resolve")
    register(input: RegisterInput @spread): RegisterResponse! @field(resolver: "Joselfonseca\\LighthouseGraphQLPassport\\GraphQL\\Mutations\\Register@resolve")
    socialLogin(input: SocialLoginInput! @spread): AuthPayload! @field(resolver: "Joselfonseca\\LighthouseGraphQLPassport\\GraphQL\\Mutations\\SocialLogin@resolve")
    verifyEmail(input: VerifyEmailInput! @spread): AuthPayload! @field(resolver: "Joselfonseca\\LighthouseGraphQLPassport\\GraphQL\\Mutations\\VerifyEmail@resolve")
    updatePassword(input: UpdatePassword! @spread): UpdatePasswordResponse! @field(resolver: "Joselfonseca\\LighthouseGraphQLPassport\\GraphQL\\Mutations\\UpdatePassword@resolve") @guard(with: ["api"])
}
Then remove the extend word
type Mutation {
    login(input: LoginInput @spread): AuthPayload! @field(resolver: "Joselfonseca\\LighthouseGraphQLPassport\\GraphQL\\Mutations\\Login@resolve")
    refreshToken(input: RefreshTokenInput @spread): RefreshTokenPayload! @field(resolver: "Joselfonseca\\LighthouseGraphQLPassport\\GraphQL\\Mutations\\RefreshToken@resolve")
    logout: LogoutResponse! @field(resolver: "Joselfonseca\\LighthouseGraphQLPassport\\GraphQL\\Mutations\\Logout@resolve")
    forgotPassword(input: ForgotPasswordInput! @spread): ForgotPasswordResponse! @field(resolver: "Joselfonseca\\LighthouseGraphQLPassport\\GraphQL\\Mutations\\ForgotPassword@resolve")
    updateForgottenPassword(input: NewPasswordWithCodeInput @spread): ForgotPasswordResponse! @field(resolver: "Joselfonseca\\LighthouseGraphQLPassport\\GraphQL\\Mutations\\ResetPassword@resolve")
    register(input: RegisterInput @spread): RegisterResponse! @field(resolver: "Joselfonseca\\LighthouseGraphQLPassport\\GraphQL\\Mutations\\Register@resolve")
    socialLogin(input: SocialLoginInput! @spread): AuthPayload! @field(resolver: "Joselfonseca\\LighthouseGraphQLPassport\\GraphQL\\Mutations\\SocialLogin@resolve")
    verifyEmail(input: VerifyEmailInput! @spread): AuthPayload! @field(resolver: "Joselfonseca\\LighthouseGraphQLPassport\\GraphQL\\Mutations\\VerifyEmail@resolve")
    updatePassword(input: UpdatePassword! @spread): UpdatePasswordResponse! @field(resolver: "Joselfonseca\\LighthouseGraphQLPassport\\GraphQL\\Mutations\\UpdatePassword@resolve") @guard(with: ["api"])
}
You should now have your schema files like this

graphql/auth.graphql
input LoginInput {
    username: String!
    password: String!
}

input RefreshTokenInput {
    refresh_token: String
}

type User {
    id: ID!
    name: String!
    email: String!
}

type AuthPayload {
    access_token: String
    refresh_token: String
    expires_in: Int
    token_type: String
    user: User
}

type RefreshTokenPayload {
    access_token: String!
    refresh_token: String!
    expires_in: Int!
    token_type: String!
}

type LogoutResponse {
    status: String!
    message: String
}

type ForgotPasswordResponse {
    status: String!
    message: String
}

type RegisterResponse {
    tokens: AuthPayload
    status: RegisterStatuses!
}

type UpdatePasswordResponse {
    status: String!
    message: String
}

enum RegisterStatuses {
    MUST_VERIFY_EMAIL
    SUCCESS
}

input ForgotPasswordInput {
    email: String! @rules(apply: ["required", "email"])
}

input NewPasswordWithCodeInput {
    email: String! @rules(apply: ["required", "email"])
    token: String! @rules(apply: ["required", "string"])
    password: String! @rules(apply: ["required", "confirmed", "min:8"])
    password_confirmation: String!
}

input RegisterInput {
    name: String! @rules(apply: ["required", "string"])
    email: String! @rules(apply: ["required", "email", "unique:users,email"])
    password: String! @rules(apply: ["required", "confirmed", "min:8"])
    password_confirmation: String!
}

input SocialLoginInput {
    provider: String! @rules(apply: ["required"])
    token: String! @rules(apply: ["required"])
}

input VerifyEmailInput {
    token: String!
}

input UpdatePassword {
    old_password: String!
    password: String! @rules(apply: ["required", "confirmed", "min:8"])
    password_confirmation: String!
}
graphql/schema.graphql
"A datetime string with format `Y-m-d H:i:s`, e.g. `2018-01-01 13:00:00`."
scalar DateTime @scalar(class: "Nuwave\\Lighthouse\\Schema\\Types\\Scalars\\DateTime")
"A date string with format `Y-m-d`, e.g. `2011-05-23`."
scalar Date @scalar(class: "Nuwave\\Lighthouse\\Schema\\Types\\Scalars\\Date")

type Query {
    users: [User!]! @paginate(type: "paginator" model: "App\\User")
    user(id: ID @eq): User @find(model: "App\\User")
}

type Mutation {
    login(input: LoginInput @spread): AuthPayload! @field(resolver: "Joselfonseca\\LighthouseGraphQLPassport\\GraphQL\\Mutations\\Login@resolve")
    refreshToken(input: RefreshTokenInput @spread): RefreshTokenPayload! @field(resolver: "Joselfonseca\\LighthouseGraphQLPassport\\GraphQL\\Mutations\\RefreshToken@resolve")
    logout: LogoutResponse! @field(resolver: "Joselfonseca\\LighthouseGraphQLPassport\\GraphQL\\Mutations\\Logout@resolve")
    forgotPassword(input: ForgotPasswordInput! @spread): ForgotPasswordResponse! @field(resolver: "Joselfonseca\\LighthouseGraphQLPassport\\GraphQL\\Mutations\\ForgotPassword@resolve")
    updateForgottenPassword(input: NewPasswordWithCodeInput @spread): ForgotPasswordResponse! @field(resolver: "Joselfonseca\\LighthouseGraphQLPassport\\GraphQL\\Mutations\\ResetPassword@resolve")
    register(input: RegisterInput @spread): RegisterResponse! @field(resolver: "Joselfonseca\\LighthouseGraphQLPassport\\GraphQL\\Mutations\\Register@resolve")
    socialLogin(input: SocialLoginInput! @spread): AuthPayload! @field(resolver: "Joselfonseca\\LighthouseGraphQLPassport\\GraphQL\\Mutations\\SocialLogin@resolve")
    verifyEmail(input: VerifyEmailInput! @spread): AuthPayload! @field(resolver: "Joselfonseca\\LighthouseGraphQLPassport\\GraphQL\\Mutations\\VerifyEmail@resolve")
    updatePassword(input: UpdatePassword! @spread): UpdatePasswordResponse! @field(resolver: "Joselfonseca\\LighthouseGraphQLPassport\\GraphQL\\Mutations\\UpdatePassword@resolve") @guard(with: ["api"])
}

type User {
    id: ID!
    name: String!
    email: String!
    created_at: DateTime!
    updated_at: DateTime!
}
Lastly we need to install the GraphQL playground we will use to send queries and mutations to our GraphQL server, for that run the following command
composer require mll-lab/laravel-graphql-playground
This is ready for tenting now!

Testing the auth mutations
Let’s start by running the PHP dev server
php artisan serve
This will open the port 8000 in our localhost for us to run the project, let’s navigate to http://127.0.0.1:8000/graphql-playground and you should see the playground like this



Now let’s create a user using a simple console command so we can log in using our graphql API. In the routes/console.php file enter
Artisan::command('user', function () {
    \App\User::create([
        'name' => 'Jose Fonseca',
        'email' => 'myemail@email.com',
        'password' => bcrypt('123456789qq')
    ]);
})->describe('Create sample user');
Then run the command in the console
php artisan user
Now that we have a user to test with, lets run the following mutation in the GraphQL Playground
