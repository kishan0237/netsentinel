/**
 * @deprecated Supabase is no longer called directly from the frontend.
 * All data access goes through the FastAPI backend on Render (src/lib/api.ts).
 * This shim only exists so any stray imports fail loudly and are easy to find.
 */

export const supabase = new Proxy(
  {},
  {
    get() {
      throw new Error(
        'Direct Supabase access was removed. Use the REST API via src/lib/api.ts (Api.getScanResults etc.).'
      );
    },
  }
);
