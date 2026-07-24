Feature: Firecracker OCI-image pause and resume

  A Firecracker microVM booted from an OCI image can be paused, resumed,
  and reached again. The post-resume `machine exec` proves the guest agent
  accepted the restored execution authority and is serving verbs.

  @live
  Scenario: Firecracker OCI-image pause/resume keeps the VM reachable
    Given an isolated mvm home

    When I run mvmctl in an isolated live home with "machine create --name bdd-fc-oci-resume --image oci-archive:/tmp/sleep-image4.tar --profile dev"
    Then the command exits with code 0

    When I run mvmctl in an isolated live home with "machine start bdd-fc-oci-resume --hypervisor firecracker" with a 300 second timeout
    Then the command exits with code 0

    When I run mvmctl in an isolated live home with "machine pause bdd-fc-oci-resume --hypervisor firecracker"
    Then the command exits with code 0

    When I run mvmctl in an isolated live home with "machine resume bdd-fc-oci-resume --hypervisor firecracker"
    Then the command exits with code 0

    When I run mvmctl in an isolated live home with "machine exec bdd-fc-oci-resume -- /bin/echo post-resume-ok"
    Then the command exits with code 0
    And the output contains "post-resume-ok"

    # clean up the persistent spec and VM
    When I run mvmctl in an isolated live home with "machine rm bdd-fc-oci-resume --yes --force"
    Then the command exits with code 0
