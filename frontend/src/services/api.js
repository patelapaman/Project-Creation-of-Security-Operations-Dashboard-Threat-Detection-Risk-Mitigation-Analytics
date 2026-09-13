// ============================================================
// API CONFIGURATION
// ============================================================

const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL ||
  "http://127.0.0.1:5000/api";

// ============================================================
// COMMON HELPERS
// ============================================================

async function parseResponse(response) {
  const text = await response.text();

  if (!text) {
    return {};
  }

  try {
    return JSON.parse(text);
  } catch {
    return {
      message: text,
    };
  }
}

async function fetchData(endpoint, fallback = {}, options = {}) {
  const { throwOnError = false } = options;
  try {
    const response = await fetch(`${API_BASE_URL}/${endpoint}`, {
      method: "GET",
      headers: {
        Accept: "application/json",
      },
    });

    const data = await parseResponse(response);

    if (!response.ok) {
      const errorMessage =
        data?.message ||
        data?.error ||
        `API request failed (${response.status})`;

      console.error(`GET /${endpoint}:`, errorMessage);

      throw new Error(errorMessage);
    }

    console.log(`GET /${endpoint}:`, data);

    // Backend may return:
    // []
    // { data: [] }
    // { data: {...} }
    // {...}

    if (Array.isArray(data)) {
      return data;
    }

    if (
      data &&
      Object.prototype.hasOwnProperty.call(data, "data")
    ) {
      return data.data;
    }

    return data ?? fallback;
  } catch (error) {
    console.error(`API error: /${endpoint}`, error);

    // Return fallback so existing pages don't crash.
    if (throwOnError) throw error;
    return fallback;
  }
}

async function postData(endpoint, payload = {}) {
  try {
    const response = await fetch(`${API_BASE_URL}/${endpoint}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: JSON.stringify(payload),
    });

    const data = await parseResponse(response);

    if (!response.ok) {
      throw new Error(
        data?.message ||
          data?.error ||
          `POST request failed (${response.status})`
      );
    }

    return data;
  } catch (error) {
    console.error(`POST /${endpoint}:`, error);
    throw error;
  }
}

async function patchData(endpoint, payload = {}) {
  try {
    const response = await fetch(`${API_BASE_URL}/${endpoint}`, {
      method: "PATCH",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: JSON.stringify(payload),
    });

    const data = await parseResponse(response);

    if (!response.ok) {
      throw new Error(
        data?.message ||
          data?.error ||
          `PATCH request failed (${response.status})`
      );
    }

    return data;
  } catch (error) {
    console.error(`PATCH /${endpoint}:`, error);
    throw error;
  }
}

// ============================================================
// AUTH
// ============================================================

export async function loginRequest(email, password) {
  const data = await postData("auth/login", {
    email,
    password,
  });

  return data?.user || data;
}

export async function registerRequest(
  name,
  email,
  password
) {
  return postData("auth/register", {
    name,
    email,
    password,
  });
}

// ============================================================
// MILESTONE 1 — CORE SECURITY DATA
// ============================================================

// Dashboard
export const getStats = () =>
  fetchData("dashboard", {});

// Security Events
export const getEvents = () =>
  fetchData("events", []);

// Assets
export const getAssets = () =>
  fetchData("assets", []);

// Threats
export const getThreats = () =>
  fetchData("threats", []);

// Incidents
export const getIncidents = () =>
  fetchData("incidents", []);

// Vulnerabilities
export const getVulnerabilities = () =>
  fetchData("vulnerabilities", []);

// Analytics
export const getAnalytics = () =>
  fetchData("analytics", {});

// Profile
export const getProfile = (userId) =>
  fetchData(
    `profile/${encodeURIComponent(userId || "")}`,
    {}
  );

// Notifications
export const getNotifications = () =>
  fetchData("notifications", []);

// Section Analytics
export const getSectionAnalytics = () =>
  fetchData("section-analytics", {});

// ============================================================
// MILESTONE 2 — AI / ML DETECTION
// ============================================================

export const getM2Health = () =>
  fetchData("milestone2/health", {});

export const getM2Predictions = () =>
  fetchData("milestone2/predictions", []);

export const getM2Anomalies = () =>
  fetchData("milestone2/anomalies", []);

export const getM2ThreatSummary = () =>
  fetchData("milestone2/threat-summary", {});

export const getM2ModelPerformance = () =>
  fetchData("milestone2/model-performance", {});

export async function predictM2(payload) {
  return postData("milestone2/predict", payload);
}

// ============================================================
// MILESTONE 3 — RISK INTELLIGENCE
// ============================================================

// GET /api/v1/incidents
export const getM3Incidents = () =>
  fetchData("v1/incidents", []);

// GET /api/v1/summary
export const getM3Summary = () =>
  fetchData("v1/summary", {});

// GET /api/v1/high
export const getM3HighRisk = () =>
  fetchData("v1/high", []);

// GET /api/v1/incidents/:id
export const getM3Incident = (incidentId) =>
  fetchData(
    `v1/incidents/${encodeURIComponent(incidentId)}`,
    {}
  );

// GET /api/v1/attack-chains
export const getM3AttackChains = () =>
  fetchData("v1/attack-chains", []);

// GET /api/v1/intelligence
export const getM3Intelligence = () =>
  fetchData("v1/intelligence", []);

// ============================================================
// MILESTONE 3 — RISK CALCULATION
// ============================================================

export async function calculateM3Risk(payload) {
  return postData("v1/calculate", payload);
}

// ============================================================
// MILESTONE 3 — CREATE INCIDENT
// ============================================================

export async function createM3Incident(payload) {
  return postData("v1/incidents", payload);
}

// ============================================================
// MILESTONE 3 — UPDATE INCIDENT STATUS
// ============================================================

export async function updateM3IncidentStatus(
  incidentId,
  status
) {
  return patchData(
    `v1/incidents/${encodeURIComponent(
      incidentId
    )}/status`,
    {
      status,
    }
  );
}

// ============================================================
// MILESTONE 4 — FINAL SOC INTEGRATION
// ============================================================

// ------------------------------------------------------------
// M4 Overview
// GET /api/m4/overview
// ------------------------------------------------------------

export const getM4Overview = (params = {}) => {
  const query = new URLSearchParams();

  Object.entries(params).forEach(([key, value]) => {
    if (
      value !== undefined &&
      value !== null &&
      String(value).trim() !== ""
    ) {
      query.set(key, String(value));
    }
  });

  const queryString = query.toString();

  return fetchData(
    `m4/overview${queryString ? `?${queryString}` : ""}`,
    {},
    { throwOnError: true }
  );
};

// ------------------------------------------------------------
// M4 Security Posture
// GET /api/m4/posture
// ------------------------------------------------------------

export const getM4Posture = (range = 30) =>
  fetchData(
    `m4/posture?range=${encodeURIComponent(range)}`,
    {}
  );

// ------------------------------------------------------------
// M4 MITRE ATT&CK Techniques
// GET /api/m4/attack-techniques
// ------------------------------------------------------------

export const getM4AttackTechniques = () =>
  fetchData("m4/attack-techniques", []);

// ------------------------------------------------------------
// M4 Attack Chains
// GET /api/m4/attack-chains
// ------------------------------------------------------------

export const getM4AttackChains = () =>
  fetchData("m4/attack-chains", []);

// ------------------------------------------------------------
// M4 Security Report
// GET /api/m4/report
// ------------------------------------------------------------

export const getM4Report = () =>
  fetchData("m4/report", {});

// ------------------------------------------------------------
// M4 Analyst Feedback
// GET /api/m4/feedback
// ------------------------------------------------------------

export const getM4Feedback = () =>
  fetchData("m4/feedback", []);

// ------------------------------------------------------------
// M4 Submit Analyst Feedback
// POST /api/m4/feedback
// ------------------------------------------------------------

export async function submitM4Feedback(payload) {
  return postData("m4/feedback", payload);
}

// ============================================================
// HEALTH CHECK
// ============================================================

// Backend health endpoint is:
// GET /health
//
// API_BASE_URL normally ends with /api,
// therefore we intentionally remove /api here.

export const getBackendHealth = async () => {
  const baseUrl = API_BASE_URL.replace(/\/api\/?$/, "");

  try {
    const response = await fetch(`${baseUrl}/health`, {
      method: "GET",
      headers: {
        Accept: "application/json",
      },
    });

    const data = await parseResponse(response);

    if (!response.ok) {
      throw new Error(
        data?.message ||
          data?.error ||
          `Health check failed (${response.status})`
      );
    }

    return data;
  } catch (error) {
    console.error("Backend health error:", error);
    throw error;
  }
};

// ============================================================
// REPORT DOWNLOAD HELPERS
// ============================================================

// Download M4 CSV report directly from backend.
export function getM4ReportCsvUrl() {
  return `${API_BASE_URL}/m4/report.csv`;
}

// ============================================================
// API EXPORT
// ============================================================

export { API_BASE_URL };