export class APIRequestError extends Error {
  constructor(message, status, code) {
    super(message);
    this.name = "APIRequestError";
    this.status = status;
    this.code = code;
  }
}

export async function fetchJSON(path, options = {}) {
  let response;
  const headers = { Accept: "application/json", ...(options.headers || {}) };
  const requestOptions = { ...options, headers };
  if (options.body && typeof options.body !== "string" && !(options.body instanceof FormData)) {
    requestOptions.body = JSON.stringify(options.body);
    requestOptions.headers["Content-Type"] = "application/json";
  }
  try {
    response = await fetch(path, requestOptions);
  } catch (error) {
    throw new APIRequestError("Aegis could not reach the backend.", 0, "NETWORK_ERROR");
  }

  let body = null;
  try {
    body = await response.json();
  } catch (error) {
    throw new APIRequestError("The backend returned an invalid response.", response.status, "INVALID_RESPONSE");
  }

  if (!response.ok) {
    const apiError = body?.error || {};
    throw new APIRequestError(
      apiError.message || "The request could not be completed.",
      response.status,
      apiError.code || "REQUEST_FAILED",
    );
  }
  return body;
}
