// @vitest-environment jsdom

import "@testing-library/jest-dom/vitest";
import { cleanup, render } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { ProviderBrand } from "./provider-brand";

afterEach(cleanup);

describe("provider branding", () => {
	it("uses locally bundled SVG marks for known providers", () => {
		const { container } = render(<ProviderBrand provider="Google" />);
		expect(container.querySelector('[data-provider-brand="Google"] svg path')).toBeInTheDocument();
		expect(container.querySelector("img")).not.toBeInTheDocument();
	});

	it("renders recognizable local marks for Microsoft and LinkedIn", () => {
		const { container, rerender } = render(<ProviderBrand provider="Microsoft" />);
		expect(container.querySelectorAll(".microsoft-brand i")).toHaveLength(4);
		rerender(<ProviderBrand provider="LinkedIn" />);
		expect(container.querySelector(".linkedin-brand")).toHaveTextContent("in");
	});

	it("falls back to a two-letter monogram for custom providers", () => {
		const { container, rerender } = render(<ProviderBrand provider="Example Social" />);
		expect(container.querySelector('[data-provider-brand="custom"]')).toHaveTextContent("ES");
		rerender(<ProviderBrand provider="" />);
		expect(container.querySelector('[data-provider-brand="custom"]')).toHaveTextContent("?");
	});
});
