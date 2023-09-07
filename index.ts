/**
 * @param allowScopes {(string|Array<string>)} - Allowed or required scopes. String must be 'space' separated
 * @param options {Object} - Options
 *  - scopeKey {string} [scope] - The user property name to check for the scope. req.auth[scopeKey]
 *  - requireAll {boolean} [false] - If true: all scopes must be included. If false: at least 1
 *  - errorToNext {boolean} [false] - If true: forward errors to 'next', instead of ending the response directly
 * @returns {Function}
 */

import { Options } from "./types";

export function AuthorizeMiddleware(allowedScopes: string | Array<string>, options? : Options){
    return function handler(error: Error, request: any, response: any, next: any) {
    let allowScopes : Array<string> = [];

    if(!Array.isArray(allowedScopes)){
       allowScopes = allowedScopes.split(' ');
    }
 
   const handleError = () =>{
     const err_message = 'Insufficient scope';
    if (options && options.errorToNext){
        return next({statusCode: 403, error: 'Forbidden', message: err_message});
    }
      //  To follow RFC 6750
      //  see https://tools.ietf.org/html/rfc6750#page-7
      
      response.append(
        'WWW-Authenticate',
        `Bearer scope="${allowScopes.join(' ')}", error="${err_message}"`
      );
    response.status(403).send(err_message);
   }

    if (allowScopes.length === 0) {
      return next();
    }

    if (!request.currentUser) return handleError();

    let userScopes : Array<string> = [];
   
    userScopes = request.currentUser.scope.split(' ');

    let isAllowed;
    if (options && options.requireAll) {
      isAllowed = allowScopes.every(scope => userScopes.includes(scope));
    } else {
      isAllowed = allowScopes.some(scope => userScopes.includes(scope));
    }
    return isAllowed ? next() : handleError();
  };     
}
