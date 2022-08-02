package security

import (
	"log"

	nexus "github.com/datadrivers/go-nexus-client/nexus3"
	"github.com/datadrivers/go-nexus-client/nexus3/schema/security"
	"github.com/datadrivers/terraform-provider-nexus/internal/schema/common"
	"github.com/datadrivers/terraform-provider-nexus/internal/tools"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func ResourceSecurityUserRole() *schema.Resource {
	return &schema.Resource{
		Description: "Use this resource to manage user roles.",

		Create: resourceSecurityUserRoleCreate,
		Read:   resourceSecurityUserRoleRead,
		Update: resourceSecurityUserRoleUpdate,
		Delete: resourceSecurityUserRoleDelete,
		Exists: resourceSecurityUserRoleExists,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			"id": common.ResourceID,
			"userid": {
				Description: "The userid which is used for login",
				ForceNew:    true,
				Type:        schema.TypeString,
				Required:    true,
			},
			"firstname": {
				Description: "The first name of the user.",
				Type:        schema.TypeString,
				Required:    false,
				Optional:    false,
				Computed:    true,
			},
			"lastname": {
				Description: "The last name of the user.",
				Type:        schema.TypeString,
				Required:    false,
				Optional:    false,
				Computed:    true,
			},
			"email": {
				Description: "The email address associated with the user.",
				Type:        schema.TypeString,
				Required:    false,
				Optional:    false,
				Computed:    true,
			},
			"password": {
				Description: "The password for the user.",
				Type:        schema.TypeString,
				Required:    false,
				Sensitive:   true,
				Optional:    false,
				Computed:    true,
			},
			"roles": {
				Description: "The roles which the user has been assigned within Nexus.",
				Elem:        &schema.Schema{Type: schema.TypeString},
				Required:    true,
				Type:        schema.TypeSet,
				// TODO: how to validate that at least one role is provided in the set?
			},
			"status": {
				Default:     nil,
				Description: "The user's status, e.g. active or disabled.",
				Type:        schema.TypeString,
				Required:    false,
				Optional:    false,
				Computed:    true,
			},
			"source": {
				Description: "The identity source of the user.",
				Type:        schema.TypeString,
				Required:    false,
				Optional:    false,
				Computed:    true,
			},
		},
	}
}

func getSecurityUserRoleFromResourceData(d *schema.ResourceData) security.User {
	return security.User{
		UserID:       d.Get("userid").(string),
		FirstName:    d.Get("firstname").(string),
		LastName:     d.Get("lastname").(string),
		EmailAddress: d.Get("email").(string),
		Password:     d.Get("password").(string),
		Status:       d.Get("status").(string),
		Source:       d.Get("source").(string),
		Roles:        tools.InterfaceSliceToStringSlice(d.Get("roles").(*schema.Set).List()),
	}
}

func resourceSecurityUserRoleRead(d *schema.ResourceData, m interface{}) error {
	log.Printf("[DEBUG] Read")
	client := m.(*nexus.NexusClient)

	user, err := client.Security.User.Get(d.Id())
	if err != nil {
		return err
	}

	if user == nil {
		d.SetId("")
		return nil
	}

	d.Set("email", user.EmailAddress)
	d.Set("firstname", user.FirstName)
	d.Set("lastname", user.LastName)
	d.Set("roles", tools.StringSliceToInterfaceSlice(user.Roles))
	d.Set("status", user.Status)
	d.Set("userid", user.UserID)
	d.Set("source", user.Source)

	return nil
}

func resourceSecurityUserRoleCreate(d *schema.ResourceData, m interface{}) error {
	log.Printf("[DEBUG] Create")
	client := m.(*nexus.NexusClient)

	d.SetId(d.Get("userid").(string))

	err := resourceSecurityUserRoleRead(d, m)
	if err != nil {
		return err
	}

	user := getSecurityUserRoleFromResourceData(d)

	if err := client.Security.User.Update(d.Id(), user); err != nil {
		return err
	}

	d.SetId(user.UserID)
	return resourceSecurityUserRead(d, m)
}

func resourceSecurityUserRoleUpdate(d *schema.ResourceData, m interface{}) error {
	log.Printf("[DEBUG] Update")
	client := m.(*nexus.NexusClient)

	if d.HasChange("roles") {
		user := getSecurityUserRoleFromResourceData(d)
		if err := client.Security.User.Update(d.Id(), user); err != nil {
			return err
		}
	}
	return resourceSecurityUserRoleRead(d, m)
}

func resourceSecurityUserRoleDelete(d *schema.ResourceData, m interface{}) error {
	log.Printf("[DEBUG] Delete")
	client := m.(*nexus.NexusClient)

	apiUser, err := client.Security.User.Get(d.Id())
	if err != nil {
		return err
	}

	stateUser := getSecurityUserRoleFromResourceData(d)

	// Calculate the remaining roles after the roles
	// managed by this resource are removed.
	mb := make(map[string]struct{}, len(stateUser.Roles))
	for _, role := range stateUser.Roles {
		mb[role] = struct{}{}
	}
	var roles []string
	for _, role := range apiUser.Roles {
		if _, found := mb[role]; !found {
			roles = append(roles, role)
		}
	}

	// Update the roles in the resource state to reflect the remaining roles
	d.Set("roles", tools.StringSliceToInterfaceSlice(roles))

	// Update the user roles by removing all the roles that this
	// resource manages.
	if err := resourceSecurityUserRoleUpdate(d, m); err != nil {
		return err
	}

	d.SetId("")
	return nil
}

func resourceSecurityUserRoleExists(d *schema.ResourceData, m interface{}) (bool, error) {

	log.Printf("[DEBUG] Exists")
	client := m.(*nexus.NexusClient)

	apiUser, err := client.Security.User.Get(d.Id())
	if apiUser == nil || err != nil {
		return false, err
	}

	stateUser := getSecurityUserRoleFromResourceData(d)

	if len(apiUser.Roles) != len(stateUser.Roles) {
		return false, err
	}

	exists := make(map[string]struct{}, len(stateUser.Roles))
	for _, role := range stateUser.Roles {
		exists[role] = struct{}{}
	}
	for _, role := range apiUser.Roles {
		if _, found := exists[role]; !found {
			return false, err
		}
	}

	return true, err
}
