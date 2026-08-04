import { describe, expect, it } from "vitest";
import { createAltoChildEnvironment } from "./alto.js";

describe("Alto test-harness environment", () => {
  it("passes only the required PATH and explicit dotenv/telemetry controls to Alto", () => {
    const childEnvironment = createAltoChildEnvironment(
      {
        PATH: "/test/bin",
        GLAUX_ARBITRARY_PARENT_VARIABLE: "must-not-reach-alto",
        SENTRY_DSN: "must-not-reach-alto",
      },
      "/temporary/empty-directory",
    );

    expect(childEnvironment).toEqual({
      PATH: "/test/bin",
      DOTENV_CONFIG_PATH: "/temporary/empty-directory/.env.disabled",
      SENTRY_DSN: "",
    });
    expect(childEnvironment.GLAUX_ARBITRARY_PARENT_VARIABLE).toBeUndefined();
  });
});
