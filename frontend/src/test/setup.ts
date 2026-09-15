import "@testing-library/jest-dom/vitest";

import { cleanup } from "@testing-library/react";
import { afterEach } from "vitest";

// Vitest globals are off, so Testing Library can't register its own cleanup hook.
afterEach(() => cleanup());

// jsdom lacks scrollTo; TanStack Router's scroll restoration calls it on navigation.
window.scrollTo = () => {};
