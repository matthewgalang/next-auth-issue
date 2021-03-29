import { applyApiCookie } from 'next-universal-cookie'
import { getSession } from 'next-auth/client';
import jwt from 'next-auth/jwt'

const jwtOpts = {
    secret: process.env.JWT_SECRET,
}

function _get(req) {
    const {
        headers: {
            cookie
        }
    } = req;
    return cookie.split(';').reduce((res, item) => {
        const data = item.trim().split('=');
        return {
            ...res,
            [data[0]]: data[1]
        };
    }, {});
}
function _set(req, cookieObject) {
    const cookieArray = Object.entries(cookieObject)
    req.headers.cookie = cookieArray.map((val) => (`${val[0]}=${val[1]}`)).join(';');
    return req;
}

export async function getNewSession(params) {
    const {req, res} = params
    // decode the session token
    const decodedToken = await jwt.getToken({ ...jwtOpts, req, cookieName: "next-auth.session-token"})
    if(!decodedToken) {
        return false;
    }
    // modify the session token setting persistToken to true
    decodedToken.persistToken = true
    // Encode the session token
    const encodedToken = await jwt.encode({...jwtOpts, ...jwt, token: decodedToken})
    
    // Write cookie in new headers
    let cookies = _get(req)
    cookies["next-auth.session-token"] = encodedToken
    let newReq = _set(req, cookies)
    
    // Request 'api/auth/session' with new headers
    const session = await getSession({req: newReq, res})
    // encode the new session token
    session.encodedNewToken = await jwt.encode({...jwtOpts, ...jwt, token: session.newToken})
    if (session.newToken) {
        _handleCookie(req,res, session.encodedNewToken);
    }
    session.newCookie = newReq.headers.cookie
    return session
}

function _handleCookie(req, res, encodedNewtoken) {
    applyApiCookie(req, res);
    // write the session token
    res.cookie("next-auth.session-token", encodedNewtoken, {
        httpOnly: true,
        maxAge: 2592000, // next-auth session maxAge
        sameSite: "strict",
        path: "/",
        secure: false,
    })
}