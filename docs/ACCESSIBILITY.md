# Accessibility

azapptoolkit aims for WCAG 2.2 level AA in the desktop app.

## What the app does

- **Keyboard:** every view works without a mouse. Press `?` for the shortcut sheet; bare-key
  shortcuts are ignored while a text field or a dialog has focus. Dialogs trap focus and return
  it on close.
- **Screen readers:** controls carry accessible names, disclosures and filter chips expose their
  ARIA state, and load errors, toasts and progress are announced through live regions.
- **Display:** the app follows the operating system's dark mode and reduced-motion settings.
  Contrast has not been formally audited against AA yet; report any text that is hard to read.

## Known gaps

- Long lists are virtualized, so a screen reader announces only the rows currently rendered, not
  the full row count.
- The native macOS menu bar has no Help entries.

## Reporting a problem

Open a [bug report](https://github.com/tiredithumans/azapptoolkit/issues/new/choose) and name the
view, the assistive technology and the operating system.
