import Image from "next/image";

/**
 * The lockup, swapped by colour scheme.
 *
 * Two files rather than one recoloured with CSS, because the wordmark is not
 * a single colour: "Protect" flips between near-white and navy while "AI" and
 * ".app" stay put. A filter that inverted the lot would ruin the brand cyan.
 *
 * Both are rendered and one is hidden by media query, so the swap happens
 * without JavaScript and cannot flash the wrong one during hydration.
 */
export default function Wordmark({ className = "" }: { className?: string }) {
  return (
    <span className={className}>
      <Image
        src="/brand/lockup-on-light.png"
        alt="AIProtect"
        width={320}
        height={316}
        priority
        className="block dark:hidden"
      />
      <Image
        src="/brand/lockup-on-dark.png"
        alt=""
        aria-hidden="true"
        width={320}
        height={316}
        priority
        className="hidden dark:block"
      />
    </span>
  );
}
