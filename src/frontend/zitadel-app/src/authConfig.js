const authConfig = {
    authority: process.env.REACT_APP_OPENID_AUTHORITY,
    client_id: process.env.REACT_APP_OPENID_CLIENT_ID, //Replace this with your client id
    redirect_uri: process.env.REACT_APP_OPENID_REDIRECT_URI,
    response_type: process.env.REACT_APP_OPENID_RESPONSE_TYPE,
    scope: process.env.REACT_APP_OPENID_SCOPE, //Replace PROJECT_ID with the id of the project where the API resides.
    post_logout_redirect_uri: process.env.REACT_APP_OPENID_POST_LOGOUT_REDIRECT_URI,
    response_mode: process.env.REACT_APP_OPENID_RESPONSE_MODE,
    code_challenge_method: process.env.REACT_APP_OPENID_CODE_CHALLENGE_METHOD,
  };

 export default authConfig;
