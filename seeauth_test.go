package seeauth

import (
	"errors"
	"testing"
	"time"
)

func TestVerify(t *testing.T) {
	type args struct {
		cLife time.Duration
		sLife time.Duration
	}
	tests := []struct {
		name    string
		args    args
		wantErr error
	}{
		{
			name: "user and seedao all verify success",
			args: args{
				cLife: 12 * time.Second,
				sLife: 12 * time.Second,
			},
			wantErr: nil,
		},
		{
			name: "user verify success but seedao failed",
			args: args{
				cLife: 12 * time.Second,
				sLife: -12 * time.Second,
			},
			wantErr: errors.New("Expired Message: Message expired"),
		},
		{
			name: "seedao verify success but user failed",
			args: args{
				cLife: -12 * time.Second,
				sLife: 12 * time.Second,
			},
			wantErr: errors.New("Expired Message: Message expired"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			seeAuth, err := signOfTwoWallets(tt.args.cLife, tt.args.sLife)
			if err != nil {
				t.Errorf("signOfTwoWallets() error = %v", err)
				return
			}

			err = Verify(seeAuth)
			if tt.wantErr == nil {
				if err != nil {
					t.Errorf("Verify() error = %v, wantErr = %v", err, tt.wantErr)
				}
			} else {

				if err.Error() != tt.wantErr.Error() {
					t.Errorf("Verify() error = %v, wantErr = %v", err, tt.wantErr)
				}
			}
		})
	}
}
