package permissions

import (
	"bytes"
	"testing"

	"github.com/go-quicktest/qt"
	"github.com/spf13/cobra"
)

// pinnedSection is what Section rendered for this list before levels existed. A Set
// that declares no levels must keep rendering exactly these bytes, because a
// deployment may already apply what the command prints.
const pinnedSection = `{
  "services": [
    {
      "key": "projects",
      "displayName": "Projects",
      "permissions": [
        {
          "feature": "task",
          "act": "view",
          "description": "View a task",
          "class": "ordinary",
          "plane": "object",
          "labels": {
            "lv": "Skatīt uzdevumu"
          },
          "seeds": [
            "worker"
          ]
        },
        {
          "feature": "setup",
          "act": "import",
          "description": "Apply a file",
          "class": "tenantConfiguration",
          "plane": "tenant",
          "retired": true
        }
      ]
    }
  ]
}`

func pinnedSet(t *testing.T) *Set {
	t.Helper()
	s, err := New("projects", "Projects", []Permission{
		{Feature: "task", Act: "view", Description: "View a task", Class: Ordinary, Plane: Object,
			Labels: map[string]string{"lv": "Skatīt uzdevumu"}, Seeds: []string{"worker"}},
		{Feature: "setup", Act: "import", Description: "Apply a file", Class: TenantConfiguration, Plane: Tenant,
			Retired: true},
	})
	qt.Assert(t, qt.IsNil(err))

	return s
}

func TestSectionWithoutLevelsKeepsItsBytes(t *testing.T) {
	doc, err := pinnedSet(t).Section()
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(string(doc), pinnedSection))
}

func TestCommandWithoutLevelsKeepsItsOutput(t *testing.T) {
	var out bytes.Buffer
	cmd := pinnedSet(t).Command()
	cmd.SetOut(&out)
	root := &cobra.Command{Use: "svc"}
	root.AddCommand(cmd)
	root.SetOut(&out)
	root.SetArgs([]string{"permissions"})
	qt.Assert(t, qt.IsNil(root.Execute()))
	qt.Assert(t, qt.Equals(out.String(), pinnedSection+"\n"))
}
