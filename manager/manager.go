package manager

type Client struct {

}

type ResourceOwner struct {

}

type AccessToken struct {

}

type RefreshToken struct {

}

type AuthorizationCode struct {

}

type Delegate interface {
	LoadAccessToken() *AccessToken
}

type Manager struct {

}
