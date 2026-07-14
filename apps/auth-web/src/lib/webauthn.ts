function decode(value: string): ArrayBuffer {
  const padded = value.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - value.length % 4) % 4);
  const bytes = Uint8Array.from(atob(padded), (character) => character.charCodeAt(0));
  return bytes.buffer;
}
function encode(value: ArrayBuffer): string {
  const bytes = new Uint8Array(value);
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function creationOptions(publicKey: any): PublicKeyCredentialCreationOptions {
  return { ...publicKey, challenge: decode(publicKey.challenge), user: { ...publicKey.user, id: decode(publicKey.user.id) }, excludeCredentials: publicKey.excludeCredentials?.map((item:any)=>({...item,id:decode(item.id)})) };
}
function requestOptions(publicKey:any):PublicKeyCredentialRequestOptions {
  return { ...publicKey, challenge:decode(publicKey.challenge), allowCredentials:publicKey.allowCredentials?.map((item:any)=>({...item,id:decode(item.id)})) };
}
function registration(credential:PublicKeyCredential){const response=credential.response as AuthenticatorAttestationResponse;return{id:credential.id,rawId:encode(credential.rawId),type:credential.type,response:{attestationObject:encode(response.attestationObject),clientDataJSON:encode(response.clientDataJSON)},clientExtensionResults:credential.getClientExtensionResults()};}
function assertion(credential:PublicKeyCredential){const response=credential.response as AuthenticatorAssertionResponse;return{id:credential.id,rawId:encode(credential.rawId),type:credential.type,response:{authenticatorData:encode(response.authenticatorData),clientDataJSON:encode(response.clientDataJSON),signature:encode(response.signature),userHandle:response.userHandle?encode(response.userHandle):null},clientExtensionResults:credential.getClientExtensionResults()};}
async function json(response:Response){if(!response.ok)throw new Error('authentication failed');return response.json();}
export async function registerPasskey(username:string,displayName:string,friendlyName:string){const start=await json(await fetch('/webauthn/register/start',{method:'POST',credentials:'same-origin',headers:{'content-type':'application/json'},body:JSON.stringify({username,display_name:displayName})}));const credential=await navigator.credentials.create({publicKey:creationOptions(start.public_key)}) as PublicKeyCredential|null;if(!credential)throw new Error('authentication failed');const finish=await fetch('/webauthn/register/finish',{method:'POST',credentials:'same-origin',headers:{'content-type':'application/json'},body:JSON.stringify({ceremony_id:start.ceremony_id,credential:registration(credential),friendly_name:friendlyName})});if(!finish.ok)throw new Error('authentication failed');}
export async function authenticatePasskey(username:string){const start=await json(await fetch('/webauthn/authenticate/start',{method:'POST',credentials:'same-origin',headers:{'content-type':'application/json'},body:JSON.stringify({username})}));const credential=await navigator.credentials.get({publicKey:requestOptions(start.public_key)}) as PublicKeyCredential|null;if(!credential)throw new Error('authentication failed');const finish=await fetch('/webauthn/authenticate/finish',{method:'POST',credentials:'same-origin',headers:{'content-type':'application/json'},body:JSON.stringify({ceremony_id:start.ceremony_id,credential:assertion(credential)})});if(!finish.ok)throw new Error('authentication failed');}
export async function enrollPasskey(friendlyName:string){const start=await json(await fetch('/account/passkeys/enroll/start',{method:'POST',credentials:'same-origin',headers:{'content-type':'application/json','x-piquel-csrf':'1'},body:'{}'}));const credential=await navigator.credentials.create({publicKey:creationOptions(start.public_key)}) as PublicKeyCredential|null;if(!credential)throw new Error('authentication failed');const finish=await fetch('/account/passkeys/enroll/finish',{method:'POST',credentials:'same-origin',headers:{'content-type':'application/json','x-piquel-csrf':'1'},body:JSON.stringify({ceremony_id:start.ceremony_id,credential:registration(credential),friendly_name:friendlyName})});if(!finish.ok)throw new Error('authentication failed');}
export const webauthnAvailable=()=>typeof window!=='undefined'&&window.isSecureContext&&'PublicKeyCredential'in window;
