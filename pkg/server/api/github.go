package api

import (
	"context"
	"fmt"
	"github.com/bradleyfalzon/ghinstallation"
	"github.com/robfig/cron/v3"
	"github.com/shurcooL/githubv4"
	"log"
	"net/http"
)

const (
	pageLength = 100
	cronRate   = "5m"
)

func (c *Api) getClient() *githubv4.Client {
	tr := http.DefaultTransport

	itr, err := ghinstallation.NewKeyFromFile(
		tr, c.conf.Github.AppId, c.conf.Github.InstallationId, c.conf.Github.PrivateKeyPath)
	if err != nil {
		log.Fatal(err)
	}

	return githubv4.NewClient(&http.Client{Transport: itr})
}

func (c *Api) queryGit() (map[string]string, error) {
	client := c.getClient()

	var query struct {
		Organization struct {
			SamlIdentityProvider struct {
				SsoUrl             githubv4.String
				ExternalIdentities struct {
					Edges []struct {
						Node struct {
							Guid         githubv4.ID
							SamlIdentity struct {
								NameId githubv4.String
							}
							User struct {
								Login githubv4.String
							}
						}
					}
					PageInfo struct {
						HasNextPage githubv4.Boolean
						EndCursor   githubv4.String
					}
				} `graphql:"externalIdentities(first:$pageLength, after:$cursor)"`
			}
		} `graphql:"organization(login:$organization)"`
	}
	variables := map[string]interface{}{
		"organization": githubv4.String("squareup"),
		"cursor":       (*githubv4.String)(nil),
		"pageLength":   githubv4.Int(pageLength),
	}

	mapping := map[string]string{}
	for {
		if err := client.Query(context.Background(), &query, variables); err != nil {
			return nil, err
		}

		for _, edge := range query.Organization.SamlIdentityProvider.ExternalIdentities.Edges {
			gitLogin := string(edge.Node.User.Login)
			ssoLogin := string(edge.Node.SamlIdentity.NameId)
			if gitLogin != "" && ssoLogin != "" {
				mapping[ssoLogin] = gitLogin
			}
		}

		pageInfo := query.Organization.SamlIdentityProvider.ExternalIdentities.PageInfo
		if !pageInfo.HasNextPage {
			break
		}
		variables["cursor"] = pageInfo.EndCursor
	}

	return mapping, nil
}

func (c *Api) queryCache(ssoIdentity string) (string, error) {
	return c.storage.QueryGithubMapping(ssoIdentity)
}

func (c *Api) storeCache() {
	mapping, err := c.queryGit()
	if err != nil {
		c.logger.Errorf("unable to retrieve github mapping: %s", err)
	}

	if err := c.storage.RecordGithubMapping(mapping); err != nil {
		c.logger.Errorf("unable to record github mapping: %s", err)
	}
}

func (c *Api) RetrieveGithubUsername(ssoIdentity string) (string, error) {
	user, err := c.queryCache(ssoIdentity)

	if err != nil {
		return "", fmt.Errorf("unable to find user %s in github mapping: %s", ssoIdentity, err)
	}

	return user, nil
}

func (c *Api) StartGitCron() error {
	// The cron doesn't initially run, so we run it first before kick off the cron
	c.storeCache()
	job := cron.New()
	if _, err := job.AddFunc(fmt.Sprintf("@every %s", cronRate), c.storeCache); err != nil {
		return err
	}
	job.Start()

	return nil
}
