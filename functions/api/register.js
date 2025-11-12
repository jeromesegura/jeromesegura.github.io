// functions/api/register.js

const ALLOWED_ORIGIN = 'https://jeromesegura.com';

export async function onRequest(context) {
    const request = context.request;
    const origin = request.headers.get('Origin');
    
    // Standard CORS headers for your domain
    const corsHeaders = {
        'Access-Control-Allow-Origin': origin === ALLOWED_ORIGIN ? origin : ALLOWED_ORIGIN,
        'Access-Control-Allow-Methods': 'POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Access-Control-Max-Age': '86400', 
    };

    if (request.method === 'OPTIONS') {
        return new Response(null, { status: 204, headers: corsHeaders });
    }

    if (request.method !== 'POST') {
        return new Response('Method Not Allowed', { status: 405 });
    }

    try {
        const data = await request.json();
        const { email, password } = data; // Note: using 'email' instead of 'username'
        
        // --- REAL REGISTRATION LOGIC GOES HERE ---
        // 1. Check if the email already exists in the database.
        // 2. Hash the password securely.
        // 3. Save the new user record.
        
        // SIMULATION: Assume registration is always successful
        if (!email || !password) {
             return new Response(JSON.stringify({ message: 'Missing email or password.' }), { 
                status: 400,
                headers: { 'Content-Type': 'application/json', ...corsHeaders } 
            });
        }

        const responseBody = JSON.stringify({ message: `Account for ${email} successfully created!`, success: true });
        
        return new Response(responseBody, {
            status: 201, // 201 Created is the standard status for successful creation
            headers: { 
                'Content-Type': 'application/json',
                ...corsHeaders
            },
        });

    } catch (error) {
        return new Response(JSON.stringify({ message: 'Invalid request body format.' }), { 
            status: 400,
            headers: { 'Content-Type': 'application/json', ...corsHeaders } 
        });
    }
}