import {onError} from '@apollo/client/link/error';

let reloading = false;

/**
 * When the webserver requires sign-in, an expired session makes GraphQL requests fail with 401.
 * Reloading the page sends the browser through the sign-in flow and back to the current page.
 */
export const sessionExpiredLink = onError(({networkError}) => {
  if (
    !reloading &&
    networkError &&
    'statusCode' in networkError &&
    networkError.statusCode === 401
  ) {
    reloading = true;
    window.location.reload();
  }
});
