<?php

namespace Glueful\Extensions\Aegis\Repositories;

use Glueful\Repository\BaseRepository;
use Glueful\Extensions\Aegis\Models\UserPermission;
use Glueful\Helpers\Utils;

/**
 * User Permission Repository
 *
 * Handles direct user-permission assignments
 *
 * Features:
 * - Direct permission grants/revokes
 * - Resource-level filtering
 * - Temporal constraint handling
 * - Permission overrides
 */
class UserPermissionRepository extends BaseRepository
{
    protected string $table = 'user_permissions';
    protected array $defaultFields = [
        'uuid', 'user_uuid', 'permission_uuid', 'resource_filter',
        'constraints', 'granted_by', 'expires_at', 'created_at'
    ];
    protected bool $hasUpdatedAt = false;

    // Static cache to prevent duplicate queries across all instances within a single
    // request. Deliberately the ONLY in-process cache layer: every repository instance
    // (provider, services, controllers) shares it, so invalidation reaches them all.
    /** @var array<string, list<UserPermission>> */
    private static array $userPermissionsCache = [];

    /**
     * Drop every cached permission list for one user (all filter variants).
     * Must be called whenever the user's direct grants change, or stale
     * grants stay effective for the rest of the process.
     */
    public static function forgetUserGlobalCache(string $userUuid): void
    {
        foreach (array_keys(self::$userPermissionsCache) as $cacheKey) {
            if (str_starts_with($cacheKey, $userUuid . '_')) {
                unset(self::$userPermissionsCache[$cacheKey]);
            }
        }
    }

    public static function flushGlobalCache(): void
    {
        self::$userPermissionsCache = [];
    }

    public function getTableName(): string
    {
        return $this->table;
    }

    public function create(array $data): string
    {
        if (!isset($data['uuid'])) {
            $data['uuid'] = Utils::generateNanoID();
        }

        $success = $this->db->table($this->table)->insert($data);

        if (!$success) {
            throw new \RuntimeException('Failed to create user permission');
        }

        return $data['uuid'];
    }

    /**
     * @param array<string, mixed> $data
     */
    public function createUserPermission(array $data): ?UserPermission
    {
        $uuid = $this->create($data);
        return $this->findUserPermissionByUuid($uuid);
    }

    public function findUserPermissionByUuid(string $uuid): ?UserPermission
    {
        $result = $this->db->table($this->table)
            ->select($this->defaultFields)
            ->where(['uuid' => $uuid])
            ->limit(1)
            ->get();

        return $result ? new UserPermission($result[0]) : null;
    }

    /**
     * @param array<string, mixed> $data
     */
    public function update(string $uuid, array $data): bool
    {
        return (bool) $this->db->table($this->table)->where(['uuid' => $uuid])->update($data);
    }

    public function delete(string $uuid): bool
    {
        return (bool) $this->db->table($this->table)->where(['uuid' => $uuid])->delete();
    }

    /**
     * @param array<string, mixed> $filters
     * @return list<UserPermission>
     */
    public function findByUser(string $userUuid, array $filters = []): array
    {
        // Create cache key based on user UUID and filters
        $cacheKey = $userUuid . '_' . md5(serialize($filters));

        if (isset(self::$userPermissionsCache[$cacheKey])) {
            return self::$userPermissionsCache[$cacheKey];
        }

        $query = $this->db->table($this->table)
            ->select($this->defaultFields)
            ->where(['user_uuid' => $userUuid]);

        if (isset($filters['permission_uuid'])) {
            $query->where(['permission_uuid' => $filters['permission_uuid']]);
        }

        if (isset($filters['active_only']) && $filters['active_only']) {
            $currentTime = $this->db->getDriver()->formatDateTime();
            $query->where(function ($q) use ($currentTime) {
                $q->where('expires_at', '>=', $currentTime)
                  ->orWhereNull('expires_at');
            });
        }

        $query->orderBy(['created_at' => 'DESC']);

        $results = $query->get();
        $userPermissions = array_map(fn($row) => new UserPermission($row), $results);

        // Cache the result
        self::$userPermissionsCache[$cacheKey] = $userPermissions;

        return $userPermissions;
    }

    /**
     * @return list<UserPermission>
     */
    public function findByPermission(string $permissionUuid): array
    {
        $results = $this->db->table($this->table)
            ->select($this->defaultFields)
            ->where(['permission_uuid' => $permissionUuid])
            ->orderBy(['created_at' => 'DESC'])
            ->get();

        return array_map(fn($row) => new UserPermission($row), $results);
    }

    public function findUserPermission(string $userUuid, string $permissionUuid): ?UserPermission
    {
        $result = $this->db->table($this->table)
            ->select($this->defaultFields)
            ->where([
                'user_uuid' => $userUuid,
                'permission_uuid' => $permissionUuid
            ])
            ->limit(1)
            ->get();

        return $result ? new UserPermission($result[0]) : null;
    }

    /**
     * @param array<string, mixed> $resourceContext
     */
    public function hasUserPermission(string $userUuid, string $permissionUuid, array $resourceContext = []): bool
    {
        $query = $this->db->table($this->table)
            ->select(['uuid'])
            ->where([
                'user_uuid' => $userUuid,
                'permission_uuid' => $permissionUuid
            ]);

        // Check if permission is still active (not expired)
        $currentTime = $this->db->getDriver()->formatDateTime();
        $query->where(function ($q) use ($currentTime) {
            $q->where('expires_at', '>=', $currentTime)
              ->orWhereNull('expires_at');
        });

        $results = $query->get();

        if (empty($results)) {
            return false;
        }

        // If we have resource context, check resource filters
        if (!empty($resourceContext)) {
            foreach ($results as $row) {
                $userPermission = new UserPermission($row);
                if ($userPermission->matchesResource($resourceContext)) {
                    return true;
                }
            }
            return false;
        }

        return true;
    }

    /**
     * @param array<string, mixed> $context
     * @return list<UserPermission>
     */
    public function getUserPermissions(string $userUuid, array $context = []): array
    {
        $query = $this->db->table($this->table)
            ->select($this->defaultFields)
            ->where(['user_uuid' => $userUuid]);

        // Only get active (non-expired) permissions
        $currentTime = $this->db->getDriver()->formatDateTime();
        $query->where(function ($q) use ($currentTime) {
            $q->where('expires_at', '>=', $currentTime)
              ->orWhereNull('expires_at');
        });

        $results = $query->get();
        $userPermissions = array_map(fn($row) => new UserPermission($row), $results);

        // Filter by context if provided
        if (!empty($context)) {
            $userPermissions = array_filter($userPermissions, function ($permission) use ($context) {
                return $permission->satisfiesConstraints($context);
            });
        }

        return array_values($userPermissions);
    }

    public function revokeUserPermission(string $userUuid, string $permissionUuid): bool
    {
        return (bool) $this->db->table($this->table)->where([
            'user_uuid' => $userUuid,
            'permission_uuid' => $permissionUuid
        ])->delete();
    }

    public function revokeAllUserPermissions(string $userUuid): bool
    {
        return (bool) $this->db->table($this->table)->where(['user_uuid' => $userUuid])->delete();
    }

    /**
     * @return list<UserPermission>
     */
    public function findExpiredPermissions(): array
    {
        $currentTime = $this->db->getDriver()->formatDateTime();
        $results = $this->db->table($this->table)
            ->select($this->defaultFields)
            ->where('expires_at', '<', $currentTime)
            ->orderBy(['expires_at' => 'ASC'])
            ->get();

        return array_map(fn($row) => new UserPermission($row), $results);
    }

    public function cleanupExpiredPermissions(): int
    {
        $currentTime = $this->db->getDriver()->formatDateTime();

        $count = $this->db->table($this->table)
            ->whereNotNull('expires_at')
            ->where('expires_at', '<', $currentTime)
            ->count();

        if ($count > 0) {
            // Create a temporary query builder for delete
            $deleteQuery = $this->db->table($this->table)
                ->select(['uuid'])
                ->whereNotNull('expires_at')
                ->where('expires_at', '<', $currentTime);

            $expiredUuids = array_column($deleteQuery->get(), 'uuid');
            if (!empty($expiredUuids)) {
                $this->bulkDelete($expiredUuids);
            }
        }

        return $count;
    }

    /**
     * @return list<UserPermission>
     */
    public function findByGrantedBy(string $grantedByUuid): array
    {
        $results = $this->db->table($this->table)
            ->select($this->defaultFields)
            ->where(['granted_by' => $grantedByUuid])
            ->orderBy(['created_at' => 'DESC'])
            ->get();

        return array_map(fn($row) => new UserPermission($row), $results);
    }

    /**
     * @param array<string, mixed> $filters
     */
    public function countUserPermissions(string $userUuid, array $filters = []): int
    {
        $query = $this->db->table($this->table)
            ->where(['user_uuid' => $userUuid]);

        if (isset($filters['active_only']) && $filters['active_only']) {
            $currentTime = $this->db->getDriver()->formatDateTime();
            $query->where(function ($q) use ($currentTime) {
                $q->where('expires_at', '>=', $currentTime)
                  ->orWhereNull('expires_at');
            });
        }

        return $query->count();
    }

    /**
     * @param array<string, mixed> $filters
     */
    public function countAllUserPermissions(array $filters = []): int
    {
        $query = $this->db->table($this->table);

        if (isset($filters['active_only']) && $filters['active_only']) {
            $currentTime = $this->db->getDriver()->formatDateTime();
            $query->where(function ($q) use ($currentTime) {
                $q->where('expires_at', '>=', $currentTime)
                  ->orWhereNull('expires_at');
            });
        }

        return $query->count();
    }
}
