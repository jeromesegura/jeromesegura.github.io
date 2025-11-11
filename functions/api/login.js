// functions/api/login.js

const ALLOWED_ORIGIN = 'https://jeromesegura.com';

export async function onRequest(context) {
    const request = context.request;
    const origin = request.headers.get('Origin');
    
    const corsHeaders = {
        'Access-Control-Allow-Origin': origin === ALLOWED_ORIGIN ? origin : ALLOWED_ORIGIN,
        'Access-Control-Allow-Methods': 'POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Access-Control-Max-Age': '86400', 
    };

    // 1. Handle CORS Preflight (OPTIONS request)
    if (request.method === 'OPTIONS') {
        return new Response(null, {
            status: 204,
            headers: corsHeaders,
        });
    }

    // Reject methods other than POST
    if (request.method !== 'POST') {
        return new Response('Method Not Allowed', { status: 405 });
    }

    // 2. Process the POST request
    try {
        const data = await request.json();
        const { username, password } = data;

        // --- SIMULATED AUTHENTICATION LOGIC (Replace with real logic later) ---
        const success = (username === 'admin' && password === 'securepassword');
        
        let responseBody;
        let status;

        if (success) {
            responseBody = JSON.stringify({ message: 'Login successful!', user: username });
            status = 200;
        } else {
            responseBody = JSON.stringify({ message: 'Invalid username or password.' });
            status = 401; // 401 Unauthorized
        }

        return new Response(responseBody, {
            status: status,
            headers: { 
                'Content-Type': 'application/json',
                ...corsHeaders // Include CORS headers in the POST response
            },
        });

    } catch (error) {
        // Handle bad JSON format
        return new Response(JSON.stringify({ message: 'Invalid request body format.' }), { 
            status: 400,
            headers: { 'Content-Type': 'application/json', ...corsHeaders } 
        });
    }
}