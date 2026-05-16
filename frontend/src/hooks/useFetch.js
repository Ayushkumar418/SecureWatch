import { useState, useEffect, useCallback } from "react";
import { REFRESH_MS } from "../config";

/**
 * useFetch — auto-refreshing data fetcher.
 * @param {string} url       — endpoint to GET
 * @param {Array}  deps      — extra deps that trigger a re-fetch (e.g. filter state)
 * @param {boolean} autoRefresh — enable/disable the 10s polling (default true)
 */
export function useFetch(url, deps = [], autoRefresh = true) {
  const [data, setData]    = useState(null);
  const [loading, setLoad] = useState(true);
  const [error, setError]  = useState(null);

  const load = useCallback(async () => {
    try {
      setLoad(true);
      const r = await fetch(url);
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      setData(await r.json());
      setError(null);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoad(false);
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [url]);

  useEffect(() => { load(); }, [load, ...deps]);

  useEffect(() => {
    if (!autoRefresh) return;
    const t = setInterval(load, REFRESH_MS);
    return () => clearInterval(t);
  }, [load, autoRefresh]);

  return { data, loading, error, reload: load };
}
