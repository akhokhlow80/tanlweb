package users

import (
	"akhokhlow80/tanlweb/admin/auth"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
)

type UserProfile struct {
	Name   string
	Fee    string // empty means no fee
	Scopes auth.Scopes
}

type User struct {
	UUID      uuid.UUID
	Profile   UserProfile
	PaidUntil time.Time // zero means not paid yet
	IsBanned  bool
}

type UserProfileParseErrors struct {
	InvalidName bool
}

func (errs *UserProfileParseErrors) ok() bool {
	return !(errs.InvalidName)
}

func (errs *UserProfileParseErrors) Error() string {
	var reasons []string
	if errs.InvalidName {
		reasons = append(reasons, "invalid name")
	}
	return "Failed to parse node: " + strings.Join(reasons, ", ")
}

var (
	_ error = (*UserProfileParseErrors)(nil)

	userNameRegexp = regexp.MustCompile(`[a-zA-Z0-9_-]+`)
)

func ParseUserProfile(
	name string,
	fee string,
	scopes auth.Scopes,
) (UserProfile, *UserProfileParseErrors) {
	var errs UserProfileParseErrors
	if !userNameRegexp.MatchString(name) {
		errs.InvalidName = true
	}

	if !errs.ok() {
		return UserProfile{}, &errs
	}

	return UserProfile{
		Name:   name,
		Fee:    fee,
		Scopes: scopes,
	}, nil
}

func NewUser(name string, fee string, scopes auth.Scopes) (User, *UserProfileParseErrors) {
	profile, errs := ParseUserProfile(name, fee, scopes)
	if errs != nil {
		return User{}, errs
	}
	return User{
		UUID:      uuid.New(),
		Profile:   profile,
		PaidUntil: time.Time{},
		IsBanned:  false,
	}, nil
}
