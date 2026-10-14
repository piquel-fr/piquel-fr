/** piqueld's health check. It never calls auth, so auth outages do not fail it. */
export const GET = () => new Response('ok');
