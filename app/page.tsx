'use client';

import { useEffect, useRef, useState } from 'react';

// Configuration
const ALLOWED_ANDROID_HASHES = [
  "17:65:98:F6:19:E6:8D:6D:79:86:79:19:8D:C4:84:F6:F3:BC:75:8A:18:D9:94:BB:E7:1F:7E:A2:4E:63:46:AF",
  "69:BB:0F:8A:7C:55:EB:35:FF:AA:33:8F:75:2F:80:6F:4D:ED:97:F8:18:DF:ED:23:3E:FB:CB:F3:85:02:87:DD"
];
const RELATED_ORIGIN = 'kinmemodoki.net';

interface StoredCredential {
  username: string;
  id: string;
  rawId: string;
  pubKey: string;
  alg: number;
}

type LogType = 'success' | 'error' | 'info';

export default function Home() {
  const [credentials, setCredentials] = useState<StoredCredential[]>([]);
  const [username, setUsername] = useState('');
  const [useRelatedOrigin, setUseRelatedOrigin] = useState(false);
  const [useNonDiscoverable, setUseNonDiscoverable] = useState(false);
  const [selectedCredIds, setSelectedCredIds] = useState<Set<string>>(new Set());
  const [logContent, setLogContent] = useState('');
  const [statusChecks, setStatusChecks] = useState<JSX.Element[]>([]);
  const [isConfirmingClear, setIsConfirmingClear] = useState(false);
  const clearTimeoutRef = useRef<NodeJS.Timeout | null>(null);

  // Utility Functions
  const base64urlToBuffer = (str: string): ArrayBuffer => {
    let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
    const pad = base64.length % 4;
    if (pad) {
      if (pad === 2) base64 += '==';
      else if (pad === 3) base64 += '=';
      else throw new Error('Invalid base64url string!');
    }

    const binaryStr = atob(base64);
    const len = binaryStr.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
      bytes[i] = binaryStr.charCodeAt(i);
    }
    return bytes.buffer;
  };

  const bufferToBase64url = (buffer: ArrayBuffer | Uint8Array): string => {
    const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    const binaryStr = String.fromCharCode.apply(null, Array.from(bytes));
    return btoa(binaryStr).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  };

  const bufferToColonHex = (buffer: ArrayBuffer): string => {
    return Array.from(new Uint8Array(buffer))
      .map(b => b.toString(16).padStart(2, '0').toUpperCase())
      .join(':');
  };

  const log = (title: string, data: any = '', type: LogType = 'info') => {
    const now = new Date().toLocaleTimeString();
    let color = 'text-gray-400';
    if (type === 'success') color = 'text-green-400';
    if (type === 'error') color = 'text-red-400';

    const dataStr = data ? `\n${JSON.stringify(data, null, 2)}` : '';
    setLogContent(prev => `[${now}] <span class="${color}">${title}</span>${dataStr}\n\n${prev}`);
  };

  const renderStatus = (label: string, success: boolean, notes: string = '') => {
    const status = success ? 'success' : 'failure';
    const badgeText = success ? 'Available' : 'Unavailable';

    return (
      <div className="status-item" key={label}>
        <div>
          <span className="status-label">{label}</span>
          {notes && <p className="text-xs text-gray-500 mt-1" dangerouslySetInnerHTML={{ __html: notes }} />}
        </div>
        <span className={`status-badge ${status}`}>{badgeText}</span>
      </div>
    );
  };

  const derToRawSignature = (derSignature: ArrayBuffer): ArrayBuffer | null => {
    try {
      const signature = new Uint8Array(derSignature);

      if (signature[0] !== 0x30) throw new Error("Not a DER sequence.");

      let offset = 2;

      if (signature[offset] !== 0x02) throw new Error("Expected integer for r.");
      offset++;
      let rLength = signature[offset++];
      if (signature[offset] === 0x00) {
        offset++;
        rLength--;
      }
      const r = signature.slice(offset, offset + rLength);
      offset += rLength;

      if (signature[offset] !== 0x02) throw new Error("Expected integer for s.");
      offset++;
      let sLength = signature[offset++];
      if (signature[offset] === 0x00) {
        offset++;
        sLength--;
      }
      const s = signature.slice(offset, offset + sLength);

      const rawSignature = new Uint8Array(64);
      rawSignature.set(r, 32 - r.length);
      rawSignature.set(s, 64 - s.length);

      return rawSignature.buffer;
    } catch (e: any) {
      log('Failed to parse DER signature', { name: e.name, message: e.message }, 'error');
      return null;
    }
  };

  const validateOrigin = (receivedOrigin: string) => {
    const expectedWebOrigin = window.location.origin;
    let isOriginValid = false;

    if (receivedOrigin === expectedWebOrigin) {
      isOriginValid = true;
    } else if (receivedOrigin.startsWith('android:apk-key-hash:')) {
      const receivedHashBase64 = receivedOrigin.substring('android:apk-key-hash:'.length).trim();
      try {
        const receivedHashBuffer = base64urlToBuffer(receivedHashBase64);
        const receivedHashHex = bufferToColonHex(receivedHashBuffer);

        log(`Received Android Hash: ${receivedHashHex}`);

        if (ALLOWED_ANDROID_HASHES.includes(receivedHashHex)) {
          isOriginValid = true;
        }
      } catch (e: any) {
        log('Error decoding Android origin hash', e.message, 'error');
        isOriginValid = false;
      }
    }

    if (!isOriginValid) {
      throw new Error(`Origin mismatch! \nExpected Web Origin: ${expectedWebOrigin} \nOR Expected Android Hash In: [${ALLOWED_ANDROID_HASHES.join(', ')}] \nReceived: ${receivedOrigin}`);
    }
    log('✅ Origin verified');
  };

  const loadCredentialsFromStorage = async () => {
    try {
      const response = await fetch('/api/credentials');
      const creds = await response.json();
      setCredentials(creds);
    } catch (error) {
      log('Error loading credentials from server', error, 'error');
      setCredentials([]);
    }
  };

  const saveCredential = async (cred: StoredCredential) => {
    try {
      const response = await fetch('/api/credentials', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(cred),
      });

      if (!response.ok) {
        throw new Error('Failed to save credential to server');
      }

      await loadCredentialsFromStorage();
    } catch (error) {
      log('Error saving credential to server', error, 'error');
    }
  };

  const performInitialChecks = async () => {
    log('Starting environment checks...');
    const checks: JSX.Element[] = [];

    let localStorageAvailable = false;
    try {
      localStorage.setItem('__test', 'test');
      localStorage.removeItem('__test');
      localStorageAvailable = true;
    } catch (e) {
      localStorageAvailable = false;
    }
    if (!localStorageAvailable) {
      checks.push(renderStatus('Local Storage', false, 'Required for this demo to store passkeys.'));
      log('Local Storage is not available. This demo will not be able to save credentials.', null, 'error');
    }

    const webAuthnAvailable = !!window.PublicKeyCredential;
    checks.push(renderStatus('WebAuthn API', webAuthnAvailable, 'Checks for <code>window.PublicKeyCredential</code>. If this fails on Android, you may need to call <code>WebSettingsCompat</code> <code>.setWebAuthenticationSupport()</code> in your app.'));
    if (!webAuthnAvailable) {
      log('WebAuthn API not found. This browser/WebView does not support WebAuthn.', null, 'error');
    }

    let conditionalMediationAvailable = false;
    if (webAuthnAvailable && PublicKeyCredential.isConditionalMediationAvailable) {
      conditionalMediationAvailable = await PublicKeyCredential.isConditionalMediationAvailable();
    }
    checks.push(renderStatus('Conditional Mediation', conditionalMediationAvailable, 'Also known as "Passkey Autofill". May not be implemented in WebViews based on Chromium.'));

    setStatusChecks(checks);
    log('Environment checks complete.');
    loadCredentialsFromStorage();
  };

  const handleCreateCredential = async () => {
    if (!username) {
      log('Username cannot be empty.', null, 'error');
      alert('Please enter a username.');
      return;
    }
    log(`Creating passkey for username: ${username}...`);

    try {
      const challenge = crypto.getRandomValues(new Uint8Array(32));
      const rpId = useRelatedOrigin ? RELATED_ORIGIN : window.location.hostname;
      log(`Using RP ID: ${rpId}`);

      // user.idをusernameから生成
      const userId = new TextEncoder().encode(username);

      const createOptions: CredentialCreationOptions = {
        publicKey: {
          challenge,
          rp: { name: 'WebAuthn WebView Demo', id: rpId },
          user: { id: userId, name: username, displayName: username },
          pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
          authenticatorSelection: {
            userVerification: 'required',
            residentKey: useNonDiscoverable ? 'discouraged' : 'required'
          },
          timeout: 60000,
          attestation: 'none'
        }
      };

      const loggableOptions = {
        ...createOptions.publicKey,
        challenge: bufferToBase64url(challenge),
        user: { ...createOptions.publicKey!.user, id: bufferToBase64url(createOptions.publicKey!.user.id as ArrayBuffer) },
      };
      log('Calling navigator.credentials.create() with options:', loggableOptions);

      const credential = await navigator.credentials.create(createOptions) as PublicKeyCredential;
      log('navigator.credentials.create() successful!', credential, 'success');

      log('--- Verifying new credential (simulated server-side) ---');
      const response = credential.response as AuthenticatorAttestationResponse;
      const clientDataJSON = JSON.parse(new TextDecoder().decode(response.clientDataJSON));

      const challengeReceived = clientDataJSON.challenge;
      const challengeSent = bufferToBase64url(challenge);
      if (challengeReceived !== challengeSent) {
        throw new Error(`Challenge mismatch! \nExpected: ${challengeSent} \nReceived: ${challengeReceived}`);
      }
      log('✅ Challenge verified');

      validateOrigin(clientDataJSON.origin);

      if (clientDataJSON.type !== 'webauthn.create') {
        throw new Error(`Type mismatch! \nExpected: 'webauthn.create' \nReceived: '${clientDataJSON.type}'`);
      }
      log('✅ Type verified');

      const newCred: StoredCredential = {
        username: username,
        id: bufferToBase64url(credential.rawId),
        rawId: bufferToBase64url(credential.rawId),
        pubKey: bufferToBase64url(response.getPublicKey()!),
        alg: response.getPublicKeyAlgorithm()
      };
      await saveCredential(newCred);
      log('✅ Credential stored on server.', newCred, 'success');
      setUsername('');

    } catch (err: any) {
      log('Error during credential creation', { name: err.name, message: err.message }, 'error');
    }
  };

  const handleGetAssertion = async () => {
    log('Starting passkey login...');

    try {
      const selectedCreds = Array.from(selectedCredIds).map(id => ({
        type: 'public-key' as const,
        id: base64urlToBuffer(id)
      }));

      const challenge = crypto.getRandomValues(new Uint8Array(32));
      const rpId = useRelatedOrigin ? RELATED_ORIGIN : window.location.hostname;
      log(`Using RP ID: ${rpId}`);

      const getOptions: CredentialRequestOptions = {
        publicKey: {
          challenge,
          timeout: 60000,
          userVerification: 'required',
          rpId: rpId,
          ...(selectedCreds.length > 0 && { allowCredentials: selectedCreds })
        }
      };

      const loggableOptions = {
        ...getOptions.publicKey,
        challenge: bufferToBase64url(challenge),
        ...(getOptions.publicKey!.allowCredentials && {
          allowCredentials: getOptions.publicKey!.allowCredentials.map(cred => ({ ...cred, id: bufferToBase64url(cred.id as ArrayBuffer) }))
        })
      };
      log('Calling navigator.credentials.get() with options:', loggableOptions);

      const assertion = await navigator.credentials.get(getOptions) as PublicKeyCredential;
      log('navigator.credentials.get() successful!', assertion, 'success');

      log('--- Verifying assertion (simulated server-side) ---');

      const credsResponse = await fetch('/api/credentials');
      const allCreds = await credsResponse.json();
      const credToVerify = allCreds.find((c: StoredCredential) => c.id === bufferToBase64url(assertion.rawId));

      if (!credToVerify) {
        throw new Error(`Could not find credential with ID ${bufferToBase64url(assertion.rawId)} in storage.`);
      }
      log('Found matching credential in storage for verification.', credToVerify);

      const response = assertion.response as AuthenticatorAssertionResponse;
      const clientDataJSON = JSON.parse(new TextDecoder().decode(response.clientDataJSON));

      const challengeReceived = clientDataJSON.challenge;
      const challengeSent = bufferToBase64url(challenge);
      if (challengeReceived !== challengeSent) {
        throw new Error(`Challenge mismatch! \nExpected: ${challengeSent} \nReceived: ${challengeReceived}`);
      }
      log('✅ Challenge verified');

      validateOrigin(clientDataJSON.origin);

      const authenticatorData = response.authenticatorData;
      const clientDataHash = await crypto.subtle.digest('SHA-256', response.clientDataJSON);
      const signatureBase = new Uint8Array([...new Uint8Array(authenticatorData), ...new Uint8Array(clientDataHash)]);

      const publicKey = await crypto.subtle.importKey(
        'spki',
        base64urlToBuffer(credToVerify.pubKey),
        { name: 'ECDSA', namedCurve: 'P-256' },
        true,
        ['verify']
      );

      log('Imported public key for verification.');

      const rawSignature = derToRawSignature(response.signature);
      if (!rawSignature) {
        throw new Error("Failed to parse signature from authenticator.");
      }

      const signatureIsValid = await crypto.subtle.verify(
        { name: 'ECDSA', hash: { name: 'SHA-256' } },
        publicKey,
        rawSignature,
        signatureBase
      );

      if (signatureIsValid) {
        log('✅ SIGNATURE VERIFIED!', null, 'success');
        log(`Welcome back, ${credToVerify.username}!`, null, 'success');
      } else {
        throw new Error("Signature verification failed!");
      }

    } catch (err: any) {
      log('Error during assertion', { name: err.name, message: err.message }, 'error');
    }
  };

  const handleClearStorage = async () => {
    if (!isConfirmingClear) {
      setIsConfirmingClear(true);
      clearTimeoutRef.current = setTimeout(() => {
        setIsConfirmingClear(false);
        log('Clear storage action timed out.', '', 'info');
      }, 4000);
    } else {
      if (clearTimeoutRef.current) {
        clearTimeout(clearTimeoutRef.current);
      }

      try {
        const response = await fetch('/api/credentials', {
          method: 'DELETE',
        });

        if (response.ok) {
          log('Server credentials cleared.', '', 'success');
          await loadCredentialsFromStorage();
        } else {
          throw new Error('Failed to clear credentials');
        }
      } catch (error) {
        log('Error clearing credentials', error, 'error');
      }

      try {
        // Signal API を使用してクライアント側のパスキーもすべて削除
        if (window.PublicKeyCredential && 'signalAllAcceptedCredentials' in PublicKeyCredential) {
          try {
            const rpId = window.location.hostname;

            // ユーザーごとにグループ化して削除
            const userCredMap = new Map<string, string[]>();
            credentials.forEach(cred => {
              if (!userCredMap.has(cred.username)) {
                userCredMap.set(cred.username, []);
              }
            });

            // 各ユーザーに対してSignal APIを呼び出し
            for (const [username] of userCredMap) {
              await (PublicKeyCredential as any).signalAllAcceptedCredentials({
                rpId: rpId,
                userId: bufferToBase64url(new TextEncoder().encode(username)),
                allAcceptedCredentialIds: []
              });
              log(`Signaled deletion for user: ${username}`, { rpId }, 'success');
            }
          } catch (signalError: any) {
            log('Error signaling credential deletion', { name: signalError.name, message: signalError.message }, 'error');
          }
        } else {
          log('PublicKeyCredential.signalAllAcceptedCredentials() is not available in this browser.', '', 'info');
        }
      } catch (e) {
        log('Error clearing by Signal API', e, 'error');
      }

      setIsConfirmingClear(false);
    }
  };

  const toggleCredentialSelection = (id: string) => {
    setSelectedCredIds(prev => {
      const newSet = new Set(prev);
      if (newSet.has(id)) {
        newSet.delete(id);
      } else {
        newSet.add(id);
      }
      return newSet;
    });
  };

  useEffect(() => {
    performInitialChecks();
  }, []);

  return (
    <div className="bg-gray-50 text-gray-800 min-h-screen">
      <noscript>
        <div className="p-4 mb-4 text-sm text-red-800 rounded-lg bg-red-100" role="alert">
          <span className="font-medium">JavaScript is disabled!</span> WebAuthn requires JavaScript to function. Please enable it in your browser settings.
        </div>
      </noscript>

      <div id="app-container" className="max-w-2xl mx-auto p-4 sm:p-6 lg:p-8">
        <header className="text-center mb-8">
          <h1 className="text-3xl font-bold text-gray-900">WebAuthn WebView Demo</h1>
          <p className="text-gray-600 mt-2">A mobile-first experience for testing passkeys in Android WebView.</p>
        </header>

        {/* Status Checks */}
        <div id="status-checks" className="space-y-3 mb-8 p-6 bg-white rounded-xl shadow-sm border border-gray-200">
          <h2 className="text-xl font-semibold text-gray-800 mb-4 border-b pb-2">Environment Checks</h2>
          {statusChecks}
        </div>

        {/* Main Login Action */}
        <section id="login-section" className="mb-6 p-6 bg-white rounded-xl shadow-sm border border-gray-200">
          <h2 className="text-xl font-semibold text-gray-800 mb-4">1. Login with a Passkey</h2>
          <p className="text-gray-600 mb-4">Click the button below to initiate a passkey login (getAssertion).</p>
          <button
            onClick={handleGetAssertion}
            className="w-full bg-blue-600 text-white font-bold py-3 px-4 rounded-lg hover:bg-blue-700 focus:outline-none focus:ring-4 focus:ring-blue-300 transition-all duration-300 ease-in-out shadow-md"
          >
            Login with Passkey
          </button>
        </section>

        {/* Get Request Options (Collapsible) */}
        <details className="mb-6 bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
          <summary className="p-6 font-semibold text-gray-800 cursor-pointer hover:bg-gray-50">
            Login & Credential Options
          </summary>
          <div id="get-options-section" className="p-6 border-t border-gray-200 divide-y divide-gray-200">
            <div>
              <h3 className="font-medium text-gray-700 mb-3">Related Origins</h3>
              <p className="text-sm text-gray-500 mb-4">Use a different RP ID to test related origins support. This must be associated on the server via an <code>.well-known/webauthn</code> file.</p>
              <label className="flex items-center space-x-3 cursor-pointer p-3 bg-gray-50 rounded-md border hover:bg-gray-100">
                <input
                  type="checkbox"
                  checked={useRelatedOrigin}
                  onChange={(e) => setUseRelatedOrigin(e.target.checked)}
                  className="w-5 h-5 text-blue-600 bg-gray-100 border-gray-300 rounded focus:ring-blue-500 focus:ring-2"
                />
                <span className="text-gray-700 font-medium">Use <code>deephand-related-origin.netlify.app</code> as RP ID</span>
              </label>
            </div>
            <div className="pt-6">
              <h3 className="font-medium text-gray-700 mb-3">Allow specific credentials:</h3>
              <p className="text-sm text-gray-500 mb-4">If you check any credentials below, the login request will be limited to only those. If none are checked, any passkey for this site can be used.</p>
              <div id="credentials-list" className="space-y-3">
                {credentials.length === 0 ? (
                  <p className="text-gray-500">No passkeys created yet.</p>
                ) : (
                  credentials.map(cred => (
                    <label key={cred.id} className="credential-item">
                      <input
                        type="checkbox"
                        className="credential-checkbox"
                        checked={selectedCredIds.has(cred.id)}
                        onChange={() => toggleCredentialSelection(cred.id)}
                      />
                      <div className="credential-info">
                        <span className="username">{cred.username}</span>
                        <br />
                        ID: {cred.id.substring(0, 20)}...
                      </div>
                    </label>
                  ))
                )}
              </div>
            </div>
            <div className="pt-6">
              <h3 className="font-medium text-red-700 mb-3">Clear Storage</h3>
              <p className="text-sm text-gray-500 mb-4">This will permanently remove all passkeys stored by this demo on the server.</p>
              <button
                onClick={handleClearStorage}
                className={`w-full font-bold py-3 px-4 rounded-lg focus:outline-none focus:ring-4 transition-all duration-300 ease-in-out shadow-md ${
                  isConfirmingClear
                    ? 'bg-yellow-500 hover:bg-yellow-600 focus:ring-yellow-300 text-white'
                    : 'bg-red-600 hover:bg-red-700 focus:ring-red-300 text-white'
                }`}
              >
                {isConfirmingClear ? 'Are you sure? Click again to clear' : 'Clear All Stored Passkeys'}
              </button>
            </div>
          </div>
        </details>

        {/* Create Passkey (Collapsible) */}
        <details className="mb-8 bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
          <summary className="p-6 font-semibold text-gray-800 cursor-pointer hover:bg-gray-50">
            2. Create a New Passkey
          </summary>
          <div id="create-section" className="p-6 border-t border-gray-200">
            <p className="text-gray-600 mb-4">Enter a username to associate with a new passkey.</p>
            <div className="space-y-4">
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="Enter username"
                className="w-full px-3 py-2 text-gray-700 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
              <button
                onClick={handleCreateCredential}
                className="w-full bg-green-600 text-white font-bold py-3 px-4 rounded-lg hover:bg-green-700 focus:outline-none focus:ring-4 focus:ring-green-300 transition-all duration-300 ease-in-out shadow-md"
              >
                Create Passkey
              </button>
            </div>
            <div>
              <h3 className="font-medium text-gray-700 mb-3">Non-discoverable Credentials</h3>
              <label className="flex items-center space-x-3 cursor-pointer p-3 bg-gray-50 rounded-md border hover:bg-gray-100">
                <input
                  type="checkbox"
                  checked={useNonDiscoverable}
                  onChange={(e) => setUseNonDiscoverable(e.target.checked)}
                  className="w-5 h-5 text-blue-600 bg-gray-100 border-gray-300 rounded focus:ring-blue-500 focus:ring-2"
                />
                <span className="text-gray-700 font-medium">set: residentKey: discouraged</span>
              </label>
            </div>
          </div>
        </details>

        {/* Response Log */}
        <div id="response-container">
          <h3 className="text-xl font-semibold text-gray-800 mb-4">API Response & Verification Log</h3>
          <div className="bg-gray-900 text-white font-mono text-sm p-4 rounded-lg shadow-inner">
            <pre id="log-display" className="whitespace-pre-wrap break-all" dangerouslySetInnerHTML={{ __html: logContent }}></pre>
          </div>
        </div>
      </div>
    </div>
  );
}
