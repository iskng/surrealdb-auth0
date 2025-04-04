   -- Example User Table Definition (ensure email field exists)
DEFINE TABLE user SCHEMAFULL
    PERMISSIONS
        FOR select, update, delete WHERE id = $auth;

DEFINE FIELD email ON user TYPE string ASSERT string::is::email($value);
DEFINE FIELD name ON user TYPE string;
DEFINE FIELD nickname ON user TYPE string;
DEFINE FIELD picture ON user TYPE string;
DEFINE FIELD created_at ON user TYPE datetime VALUE time::now() READONLY;
DEFINE FIELD last_login ON user TYPE datetime;

-- Optional but recommended: Unique index on email
DEFINE INDEX user_email_idx ON TABLE user COLUMNS email UNIQUE;


    DEFINE TABLE debug_log SCHEMAFULL;
    DEFINE FIELD timestamp ON debug_log TYPE datetime VALUE time::now();
    DEFINE FIELD message ON debug_log TYPE string;

USE NS test DB test; -- Unclear that this is needed
     DEFINE ACCESS auth0 ON DATABASE TYPE RECORD
        WITH JWT URL "https://lynxai.us.auth0.com/.well-known/jwks.json"
        AUTHENTICATE {

            // --- Sequential Claim Checks (as before) ---

            // 1. Audience Array
            IF !$token.aud OR !$token.aud.is_array() {
                CREATE debug_log CONTENT { message: "Static Log: THROWING - Audience missing/not array" };
                THROW "Authentication failed: Audience claim (aud) is missing or not an array.";
            };
        

            // 2. API Audience (lynxai.com)
            IF "https://lynxai.com/auth" NOT IN $token.aud {
                 CREATE debug_log CONTENT { message: "Static Log: THROWING - API Audience missing" };
                THROW "Authentication failed: Required API audience ('https://lynxai.com/auth') not found in token.";
            };
         

            // 3. UserInfo Audience (Auth0 domain)
            IF "https://lynxai.us.auth0.com/userinfo" NOT IN $token.aud {
                CREATE debug_log CONTENT { message: "Static Log: THROWING - UserInfo Audience missing" };
                THROW "Authentication failed: Required UserInfo audience ('https://lynxai.us.auth0.com/userinfo') not found in token.";
            };
     

            // 4. Email Verified Exists (surrealdb.com namespace)
            IF !$token['https://surrealdb.com/email_verified'] {
                 CREATE debug_log CONTENT { message: "Static Log: THROWING - email_verified claim missing" };
                 THROW "Authentication failed: Email verified claim ('https://surrealdb.com/email_verified') is missing from token.";
            };
    
            // 5. Email Verified is True (surrealdb.com namespace)
            IF $token['https://surrealdb.com/email_verified'] != true {
                CREATE debug_log CONTENT { message: "Static Log: THROWING - email not verified" };
                THROW "Authentication failed: Email is not verified.";
            };
        

            // 6. AuthID Exists (surrealdb.com namespace) - Primary ID
            IF !$token['https://surrealdb.com/authid'] {
                 CREATE debug_log CONTENT { message: "Static Log: THROWING - authid claim missing" };
                 THROW "Authentication failed: AuthID claim ('https://surrealdb.com/authid') is missing from token.";
            };
       

            // 7. Email Exists (surrealdb.com namespace) - For storing
             IF !$token['https://surrealdb.com/email'] {
                 CREATE debug_log CONTENT { message: "Static Log: THROWING - email claim missing" };
                 THROW "Authentication failed: Email claim ('https://surrealdb.com/email') is missing from token.";
            };
         

    

            // Extract claims
            LET $authid_value = $token['https://surrealdb.com/authid'];
            LET $email_value = $token['https://surrealdb.com/email'];
            LET $name_value = $token['https://surrealdb.com/name'] ?? $email_value;
            LET $nickname_value = $token['https://surrealdb.com/nickname'] ?? '';
            LET $picture_value = $token['https://surrealdb.com/picture'] ?? '';

              LET $sanitized_authid_value = string::replace($authid_value, "|", "_"); // Replace | with _
            LET $sanitized_authid_value = string::replace($sanitized_authid_value, "-", "_"); // Replace - with _
            
            // Construct the target user Record ID
            LET $user_id = <record>('user:'+$sanitized_authid_value);
           

            LET $user_record = UPSERT $user_id SET
                email = $email_value,
                name = $name_value,
                nickname = $nickname_value,
                picture = $picture_value,
                last_login = time::now() // Update last_login every time
                // Do NOT set created_at here - rely on schema default
            ;
         
            // Check if UPSERT returned a record (it should always return one)
            IF count($user_record) = 0  {
                 CREATE debug_log CONTENT { message: "Static Log: THROWING - UPSERT failed to return a record." };
                 THROW "Authentication failed: User record could not be created or updated.";
            };

             // Extract the single record from the result array
             LET $single_user_record = $user_record[0];
          
            // Return the ID of thtte created/updated user record
            RETURN $single_user_record.id;

        } // End AUTHENTICATE
    ; // End DEFINE ACCESS