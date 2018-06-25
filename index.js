require("dotenv").config();

const express = require("express");
const session = require("express-session");
const OAuthClient = require("oauth-1-client");
const escapeHtml = require("escape-html");

const PORT = 3000;
const {
    KA_CONSUMER_KEY: CONSUMER,
    KA_CONSUMER_SECRET: SECRET,
    COOKIE_SECRET
} = process.env;
const OAUTH_CALLBACK_PATH = "/oauth_callback";
const LOGOUT_PATH = "/logout";
const KA = "www.khanacademy.org";

const app = express();

app.use(session({
    secret: COOKIE_SECRET,
    name: "sessionid",
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true
    }
}));

const internalServerError = response => err => {
    console.error(err);
    response.status(500).send("Internal server error");
};

const client = (() => {
    const callback = `http://localhost:${PORT}${OAUTH_CALLBACK_PATH}`;
    return new OAuthClient({
        key: CONSUMER,
        secret: SECRET,
        apiHostName: KA,
        requestUrl: `https://${KA}/api/auth2/request_token?oauth_callback=${callback}`,
        accessUrl: `https://${KA}/api/auth2/access_token`
    });
})();

app.get("/", (request, response) => {
    const { token, tokenSecret } = request.session;
    if (token && tokenSecret) {
        response.type("html");
        client.auth(token, tokenSecret)
            .get("/api/v1/user", { casing: "camel" })
            .then(httpResponse => httpResponse.body)
            .then(userInfo => response.send(`
                <!DOCTYPE html>
                <title>Demo</title>
                <p>You have ${userInfo.discussionBanned ? "" : "not"}
                    been banned from KA</p>
                <p>Your email: ${escapeHtml(userInfo.email)}</p>
                <p><a href="${LOGOUT_PATH}">Logout</a></p>
            `))
            .catch(internalServerError(response));
    } else {
        client.requestToken()
            .then(r => `https://www.khanacademy.org/api/auth2/authorize?oauth_token=${r.token}`)
            .then(url => response.redirect(url))
            .catch(internalServerError(response));
    }
});

app.get(OAUTH_CALLBACK_PATH, (request, response) => {
    const { query, session } = request;
    if (query && query.oauth_token && query.oauth_token_secret && query.oauth_verifier) {
        client.accessToken(
            query.oauth_token,
            query.oauth_token_secret,
            query.oauth_verifier
        ).then(r => {
            const { token, tokenSecret } = r;
            session.token = token;
            session.tokenSecret = tokenSecret;
            response.redirect("/");
        }).catch(internalServerError(response));
    } else {
        response.status(400).send("Bad request");
    }
});

app.get(LOGOUT_PATH, (request, response) =>
    request.session.regenerate(e => response.redirect("/")));

app.listen(PORT);

console.info("Running...");