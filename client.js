import { createClient } from "https://esm.sh/@supabase/supabase-js@2.118.0";

// Consent is for an OAuth connection only. It cannot approve a host operation.
const config=JSON.parse(document.getElementById("client-config").textContent);
const authorizationIds=new URL(location.href).searchParams.getAll("authorization_id");
const validId=/^[A-Za-z0-9._~-]{8,256}$/;
config.authorizationId=authorizationIds.length===1&&
  validId.test(authorizationIds[0])?authorizationIds[0]:null;
const supabase=createClient(config.projectUrl,config.publicKey,{
  auth:{autoRefreshToken:true,detectSessionInUrl:true,persistSession:true,
        storageKey:"wayne-policy-admin-consent-v1"}
});
const $=id=>document.getElementById(id);
const status=$("status"), login=$("login"),consent=$("consent"),
      complete=$("complete"),signout=$("signout");
let busy=false,details=null,priorRedirect=null;
function message(msg,error=false){
  status.textContent=msg;
  status.setAttribute("role",error?"alert":"status");
}
function view(name){
  for(const [key,node] of [["login",login],["consent",consent],
                            ["complete",complete]])node.hidden=key!==name;
}
function lock(value){
  busy=value;
  for(const id of ["email-submit","approve","deny","continue"])
    $(id).disabled=value;
}
function chatGptRedirect(value){
  if(typeof value!=="string"||value.length>4096)throw Error("Invalid redirect");
  const url=new URL(value),host=url.hostname.toLowerCase();
  // Only the two documented ChatGPT connector callback shapes.
  // A similarly named domain, arbitrary path or script fragment is refused.
  const validCallback=url.pathname==="/connector_platform_oauth_redirect"||
    /^\/connector\/oauth\/[A-Za-z0-9_-]{8,128}$/.test(url.pathname);
  if(url.origin!=="https://chatgpt.com"||url.username||
     url.password||url.hash||!validCallback)
    throw Error("Unexpected redirect destination");
  return url.href;
}
async function refresh(){
  if(busy)return;
  message("Checking account and authorization request...");
  const {data:userData}=await supabase.auth.getUser();
  if(!userData?.user){
    signout.hidden=true;view("login");
    message("Sign in using the email account invited to this project.");
    return;
  }
  signout.hidden=false;
  const {data,error}=await supabase.auth.oauth.getAuthorizationDetails(
    config.authorizationId);
  if(error||!data){
    view("login");login.hidden=true;
    message("Authorization request could not be verified. Reconnect from ChatGPT.",true);
    return;
  }
  if(!("authorization_id" in data)){
    try{priorRedirect=chatGptRedirect(data.redirect_url);}
    catch{message("Unexpected callback destination. Connection refused.",true);return;}
    view("complete");message("This connection was previously authorized.");return;
  }
  if(typeof data.client?.name!=="string"||
     typeof data.redirect_uri!=="string"||
     typeof data.scope!=="string"){
    message("Incomplete OAuth request; connection refused.",true);return;
  }
  try{chatGptRedirect(data.redirect_uri);}
  catch{message("Unexpected callback destination. Connection refused.",true);return;}
  details=data;
  $("client-name").textContent=data.client.name;
  $("callback").textContent=data.redirect_uri;
  $("scopes").textContent=data.scope.trim()||"(none requested)";
  view("consent");
  message("Review the client and permissions before deciding.");
}
$("email-form").addEventListener("submit",async(event)=>{
  event.preventDefault();
  if(busy||!config.authorizationId)return;
  const email=$("email").value.trim();
  if(!email||email.length>254){
    message("Enter your invited email address.",true);return;
  }
  lock(true);
  try{
    const redirect=new URL(location.origin+location.pathname);
    redirect.searchParams.set("authorization_id",config.authorizationId);
    const {error}=await supabase.auth.signInWithOtp({
      email,options:{shouldCreateUser:false,emailRedirectTo:redirect.href}
    });
    if(error)throw error;
    message("Check your email for the sign-in link, then return here.");
  }catch{
    message("Could not start email sign-in. Check your project invitation.",true);
  }finally{lock(false);}
});
async function decide(decision){
  if(busy||!details)return;
  lock(true);
  try{
    const {data,error}=decision==="approve"
      ? await supabase.auth.oauth.approveAuthorization(config.authorizationId)
      : await supabase.auth.oauth.denyAuthorization(config.authorizationId);
    if(error||!data?.redirect_url)throw Error("OAuth decision failed");
    // Must be an actual click. The returned URL must be a trusted ChatGPT origin.
    location.assign(chatGptRedirect(data.redirect_url));
  }catch{
    message("Unable to complete your authorization decision.",true);lock(false);
  }
}
$("approve").addEventListener("click",()=>{void decide("approve");});
$("deny").addEventListener("click",()=>{void decide("deny");});
$("continue").addEventListener("click",()=>{
  if(priorRedirect&&!busy)location.assign(priorRedirect);
});
signout.addEventListener("click",async()=>{
  if(busy)return;
  lock(true);
  try{await supabase.auth.signOut();}
  finally{lock(false);signout.hidden=true;view("login");}
});
supabase.auth.onAuthStateChange(event=>{
  if(event==="SIGNED_IN"||event==="SIGNED_OUT")
    setTimeout(()=>{void refresh().catch(()=>
      message("Unable to confirm the sign-in session.",true));},0);
});
if(window.top!==window.self){
  // Static hosts cannot set frame-ancestors. All consent controls are hidden
  // until this check runs; never render the page within a third-party frame.
  document.body.textContent="For security, open the authorization page directly.";
}else if(!config.authorizationId){
  view("login");login.hidden=true;
  message("Missing or invalid authorization request. Reconnect from ChatGPT.",true);
}else{
  void refresh().catch(()=>{
    view("login");message("Authorization service unavailable.",true);
  });
}
