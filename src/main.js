import './style.css'; // Import CSS
import Surreal from 'surrealdb'; // Import SurrealDB SDK
import { createAuth0Client } from '@auth0/auth0-spa-js'; // Import Auth0 SDK

let config = null;
let auth0Client = null;
const db = new Surreal(); // Initialize the SDK instance

// --- Move window assignments down ---
// window.login = login;
// window.logout = logout;

const fetchConfig = () => fetch("/config.json");

const configure = async () => {
	const response = await fetchConfig();
	config = await response.json();

	document.getElementById("surrealdb-endpoint").textContent = config.surrealdb_endpoint;
	document.getElementById("auth0-domain").textContent = config.auth0_domain;
	document.getElementById("auth0-client-id").textContent = config.auth0_client_id;
	document.getElementById("auth0-audience").textContent = config.auth0_audience;

	auth0Client = await createAuth0Client({
		domain: config.auth0_domain,
		clientId: config.auth0_client_id,
		authorizationParams: {
			audience: config.auth0_audience
		}
	});

	// --- Connect SurrealDB ---
    try {
        // Use the /rpc endpoint for the SDK
        const rpcEndpoint = config.surrealdb_endpoint.replace(/\/$/, '') + '/rpc';
        console.log(`Connecting SurrealDB SDK to: ${rpcEndpoint}`);
        await db.connect(rpcEndpoint);
        // Optional: Use NS/DB if needed, depends on server setup
        await db.use({ namespace: 'test', database: 'test' }); 
        console.log("SurrealDB SDK connected.");
    } catch (e) {
        console.error("SurrealDB SDK Connection Error:", e);
        // Optionally update UI to show connection error
        alert(`Failed to connect to SurrealDB: ${e.message}`); 
    }
	// --- End Connect SurrealDB ---
};

window.onload = async () => {
	await configure();
	updateUI();

	const isAuthenticated = await auth0Client.isAuthenticated();

	const query = window.location.search;
	if (query.includes("code=") && query.includes("state=")) {
		await auth0Client.handleRedirectCallback();

		updateUI();

		window.history.replaceState({}, document.title, "/");
	}
}

const updateUI = async () => {
	const isAuthenticated = await auth0Client.isAuthenticated();

	document.getElementById("btn-logout").disabled = !isAuthenticated;
	document.getElementById("btn-login").disabled = isAuthenticated;

	if (isAuthenticated) {
		document.getElementById("gated-content").classList.remove("hidden");

		document.getElementById("ipt-id-token").innerHTML = (await auth0Client.getIdTokenClaims()).__raw;
		document.getElementById("ipt-access-token").innerHTML = await auth0Client.getTokenSilently();
		document.getElementById("ipt-access-token-decoded").textContent = await decodeToken();
		document.getElementById("ipt-user-profile").textContent = JSON.stringify(await auth0Client.getUser());

		// --- Authenticate SurrealDB SDK ---
		console.log("Authenticating SurrealDB SDK...");
		const accessToken = await auth0Client.getTokenSilently();
		await db.authenticate(accessToken);
		console.log("SurrealDB SDK authenticated.");

		// --- Fetch/Update User via SDK ---
		const userData = await createUpdateUser(); // Now uses SDK
		const getUserResult = await getUser();     // Now uses SDK

		document.getElementById("ipt-sdb-getuser").textContent = JSON.stringify(getUserResult, null, 2);
		document.getElementById("ipt-sdb-createupdateuser").textContent = JSON.stringify(userData, null, 2);

	} else {
		document.getElementById("gated-content").classList.add("hidden");
		try {
		     // Ensure SDK is signed out if Auth0 is not authenticated
		     await db.invalidate();
             console.log("SurrealDB SDK invalidated on logout/session end.");
		} catch(e) { /* Ignore invalidate errors if not connected or already invalid */ }
	}
};

const login = async () => {
	await auth0Client.loginWithRedirect({
		authorizationParams: {
			redirect_uri: window.location.origin
		}
	});
};

const logout = async () => {
    // Also invalidate SDK session on logout
    try {
        await db.invalidate();
        console.log("SurrealDB SDK invalidated.");
    } catch (e) {
         console.error("Error invalidating SurrealDB session:", e);
    }
	auth0Client.logout({
		logoutParams: {
			returnTo: window.location.origin
		}
	});
};

// --- Move window assignments here, after function definitions ---
window.login = login;
window.logout = logout;
// --- End window assignments ---

// Print the decoded JWT to assist with debugging.
const decodeToken = async () => {
	const token = await auth0Client.getTokenSilently();
	const tokenParts = token.split(".");
	const decodedToken = "Header:\n" + atob(tokenParts[0]) + "\n\nPayload:\n" + atob(tokenParts[1]);
	return decodedToken
};

// Returns any users that the token is authorized to select.
// Should return only the single user matching the email in the token.
const getUser = async () => {
    console.log("SDK: Getting user...");
    try {
        // After authenticate(), db.select() uses the token's permissions
        // The 'user' table name comes from your DEFINE TABLE statement
        // Assumes your PERMISSIONS allow select based on $auth
        const result = await db.select('user');
        console.log("SDK: Got user result:", result);
        // The SDK returns an array, usually with one item if found
        return result;
    } catch (e) {
        console.error("SDK getUser Error:", e);
        throw e; // Re-throw to be caught by updateUI
    }
};

// Creates a user matching the information in the token.
// If the user already exists, updates the existing user with the new data.
const createUpdateUser = async () => {
    console.log("SDK: Creating/Updating user...");
    // We collect the user data from the Auth0 ID token.
    const auth0User = await auth0Client.getUser();

    const userData = {
        // Data to store/update in SurrealDB
        email: auth0User.email,
        name: auth0User.name,
        nickname: auth0User.nickname,
        picture: auth0User.picture
    };

    try {
        // Attempt to select the user first to decide create vs update
        // Relies on PERMISSIONS FOR select WHERE id = $auth;
        // and DEFINE ACCESS ... AUTHENTICATE ... RETURN SELECT * FROM user WHERE email = ...
        const existingUserArray = await db.select('user'); // Should return [] or [userRecord]

        let result;
        if (existingUserArray && existingUserArray.length > 0 && existingUserArray[0].id) {
            // User exists, update it using its SurrealDB Record ID
            const userId = existingUserArray[0].id; // Get the Record ID
            console.log(`SDK: Updating user ${userId} with data:`, userData);
            // Use merge to only update specified fields
            result = await db.merge(userId, userData);
            console.log("SDK: User updated:", result);
        } else {
            // User does not exist, create it.
            // Pass the data. SurrealDB should assign an ID based on DEFINE TABLE.
            console.log("SDK: Creating user with data:", userData);
            result = await db.create('user', userData);
            console.log("SDK: User created:", result);
        }
        // The SDK returns an array for create/update/merge results
        return result;
    } catch (e) {
        console.error("SDK createUpdateUser Error:", e);
        throw e; // Re-throw to be caught by updateUI
    }
};
