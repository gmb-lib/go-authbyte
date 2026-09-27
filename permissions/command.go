package permissions

import "github.com/spf13/cobra"

// Command is the `permissions` command a service registers on its command line:
// it prints the Set as the membership register's configuration section, for a
// deployment to apply there.
func (s *Set) Command() *cobra.Command {
	return &cobra.Command{
		Use:   "permissions",
		Short: "Print the permissions this service enforces, as the membership register's configuration section",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			doc, err := s.Section()
			if err != nil {
				return err
			}
			_, err = cmd.OutOrStdout().Write(append(doc, '\n'))

			return err
		},
	}
}
