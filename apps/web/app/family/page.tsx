export default function Family() {
  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-semibold">Family</h1>
      {/* Honest placeholder. The models exist; the invite and Kids-preset
          routes do not, and a screen pretending otherwise would be the
          product's own defect class in UI form. */}
      <p className="text-sm opacity-70">
        Family plans aren't ready yet. When they are, you'll be able to invite
        up to 7 people and set a Kids preset for their devices.
      </p>
    </div>
  );
}
